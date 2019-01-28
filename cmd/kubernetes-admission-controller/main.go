/*
The main entry point for the Anchore Kubernetes Admission Controller

This controller, based on the openshift generic admission server), supports Validating Webhook requests

Default behavior is ValidatingAdmissionWebhook-only mode

Configuration:
The controller relies on a pair of config inputs:
1.) Configuration json in a file, typically provided via mounted ConfigMap. Defaults to filename /config.json. Overridden by env var CONFIG_FILE_PATH
2.) Anchore client credentials, typically provided via a mounted file from a Secret, also json format. Defaults to filename /credentials.json. Overridden by env var CREDENTIALS_FILE_PATH

*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"github.com/spf13/viper"
	"reflect"
	"strings"
	"time"

	"github.com/openshift/generic-admission-server/pkg/cmd"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logz "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"os"
	"regexp"
	"sort"
	"sync"
)

var authVpr *viper.Viper
var confVpr *viper.Viper
var config ControllerConfiguration
var authConfig AnchoreAuthConfig
var log logr.Logger

var clientset *kubernetes.Clientset

type admissionHook struct {
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

const (
	credsConfigFilePathEnvVar string = "CREDENTIALS_FILE_PATH"
	configFilePathEnvVar      string = "CONFIG_FILE_PATH"
)

/*
  Match any object metadata to the selector
*/
func matchObjMetadata(selector *ResourceSelector, objMeta *metav1.ObjectMeta) (bool, error) {
	mapArray := []map[string]string{objMeta.Labels, objMeta.Annotations}
	for _, kvMap := range mapArray {
		for k, v := range kvMap {
			match, err := regexp.MatchString(selector.SelectorKeyRegex, k)
			if err != nil {
				log.Error(err, "Error evaluating regexp ", selector.SelectorKeyRegex, " against ", k)
				match = false
			}

			match2, err := regexp.MatchString(selector.SelectorValueRegex, v)
			if err != nil {
				log.Error(err, "Error evaluating regexp ", selector.SelectorValueRegex, " against ", v)
				match2 = false

			}

			if match && match2 {
				return true, nil
			}

		}
	}

	return false, nil
}

/*
  Match the image reference itself (tag)
*/
func matchImageResource(regex string, img string) (bool, error) {
	log.Info("Matching image on regexp") //"regex", regex, "image", img)
	matches, err := regexp.MatchString(regex, img)
	log.Info("Match result is ")//, matches, " with err ", err)
	return matches, err
}

/*
  Get the correct set of ObjectMeta for comparison, or nil if not a selector that uses ObjectMeta
*/
func resolveResource(selector *ResourceSelector, pod *v1.Pod) (*metav1.ObjectMeta, error) {
	log.Info("Resolving resource for selection")

	switch selector.ResourceType {
	case PodSelectorType:
		log.Info("Selecting based on pod metadata")
		return &pod.ObjectMeta, nil
	case NamespaceSelectorType:
		log.Info("Selecting based on namespace ", pod.Namespace, " metadata")
		nsFound, err := clientset.CoreV1().Namespaces().Get(pod.Namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		} else {
			return &nsFound.ObjectMeta, nil
		}
	case ImageSelectorType:
		log.Info("Selecting based on image reference")
		return nil, nil
	default:
		return nil, nil
	}
}

func (a *admissionHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	log.Info("Initializing handler")

	return nil
}

func (a *admissionHook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	return schema.GroupVersionResource{
		Group:    "admission.anchore.io",
		Version:  "v1beta1",
		Resource: "imagechecks",
	}, "imagecheck"

}

func (a *admissionHook) Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	var err error
	var pod v1.Pod
	var containers []v1.Container
	var anchoreClient *anchore.APIClient
	var authCtx context.Context
	var policyRef *AnchoreClientConfiguration

	status := &admissionv1beta1.AdmissionResponse{
		Allowed: true,
		UID:     admissionSpec.UID,
		Result:  &metav1.Status{Status: metav1.StatusSuccess, Message: ""}}

	// Handle higher-level types as well as pods, helps make error messages cleaner
	if strings.ToLower(admissionSpec.Kind.Kind) != "pod" {
		log.Info("Non-pod validation requested. No validation to do")
		return status
	}

	log.Info("Handling a Pod validation")
	err = json.Unmarshal(admissionSpec.Object.Raw, &pod)
	if err != nil {
		log.Error(err, "Could not parse the pod spec")
		status.Allowed = false
		status.Result.Status = metav1.StatusFailure
		status.Result.Reason = "Error parsing admission request pod spec"
		return status
	}
	containers = pod.Spec.Containers

	// Update the config to ensure we've got the latest
	//config, _ := refreshConfig(confVpr)

	if containers != nil && len(containers) > 0 {
		for _, container := range containers {
			image := container.Image
			log.Info("Checking image: " + image)

			log.Info("Evaluating selectors")

			policyRef = nil

			for _, selector := range config.PolicySelectors {
				log.Info("Checking selector ", selector)
				meta, err := resolveResource(&selector.Selector, &pod)
				if err != nil {
					log.Error(err, "Error checking selector, skipping ")
					continue
				}

				if meta != nil {
					if match, err := matchObjMetadata(&selector.Selector, meta); match {
						if err != nil {
							log.Error(err,"Error doing selector match on metadata")
							continue
						}

						policyRef = &selector.PolicyReference
						break
					}
				} else {
					if match, err := matchImageResource(selector.Selector.SelectorValueRegex, image); match {
						if err != nil {
							log.Error(err, "Error doing selector match on image reference")
							continue
						}
						policyRef = &selector.PolicyReference
						break
					} else {
						log.Error(err,"No match")
					}
				}
			}

			anchoreClient = nil
			authCtx = nil

			if policyRef != nil {
				for _, entry := range authConfig.Users {
					if entry.Username == policyRef.Username {
						log.Info("Found selector match for user ", entry.Username, " with policy ", policyRef.PolicyBundleId)
						anchoreClient, authCtx, _ = initClient(entry.Username, entry.Password, config.AnchoreEndpoint)
					}
				}
			}

			if (config.Validator.RequirePassPolicy || config.Validator.RequireImageAnalyzed || config.Validator.RequestAnalysis) && (anchoreClient == nil || authCtx == nil) {
				log.Error(err,"No matching selector found or not client configuration set. Failing validation")
				status.Allowed = false
				status.Result.Status = metav1.StatusFailure
				status.Result.Reason = "No policy/endpoint selector matched the request or no client credentials were available, but the validator configuration requires it"
				return status
			}

			if config.Validator.RequirePassPolicy {
				status.Allowed, status.Result.Message, err = validatePolicy(image, policyRef.PolicyBundleId, anchoreClient, authCtx)

				// If configured, do the analysis, but do not wait and do not change admission result
				if err != nil && config.Validator.RequestAnalysis {
					_, err2 := AnalyzeImage(image, anchoreClient, authCtx)
					if err2 != nil {
						log.Error(err, "During requested image analysis submission, an error occurred: ", err2)
					}
				}
			} else if config.Validator.RequireImageAnalyzed {
				status.Allowed, status.Result.Message, err = validateAnalyzed(image, anchoreClient, authCtx)

				// If configured, do the analysis, but do not wait and do not change admission result
				if err != nil && config.Validator.RequestAnalysis {
					_, err2 := AnalyzeImage(image, anchoreClient, authCtx)
					if err2 != nil {
						log.Error(err, "During requested image analysis submission, an error occurred: ", err2)
					}
				}
			} else if config.Validator.RequestAnalysis {
				log.Info("Requesting analysis of the image ", image)
				status.Allowed, status.Result.Message, err = passiveValidate(image, anchoreClient, authCtx)
			} else {
				log.Info("No check requirements in config and no analysis request configured. Allowing")
				status.Allowed = true
			}

			if !status.Allowed {
				status.Result.Status = metav1.StatusFailure
				if err != nil {
					status.Result.Message = err.Error()
				}
			}
		}
	} else {
		log.Error(err,"No container specs to validate")
	}

	log.Info("Returning status: ", status)
	return status
}

func passiveValidate(image string, client *anchore.APIClient, authCtx context.Context) (bool, string, error) {
	log.Info("Performing passive validation. Will request image analysis and always allow admission")
	var err error

	imgObj, err := AnalyzeImage(image, client, authCtx)
	if err != nil {
		log.Error(err, "Error from analysis request", err.Error())
		return true, "Allowed but could not request analysis due to error", nil
	}

	return true, fmt.Sprintf("Image analysis for image %s requested and found mapped to digest %s", image, imgObj.ImageDigest), nil
}

func validateAnalyzed(image string, client *anchore.APIClient, authCtx context.Context) (bool, string, error) {
	log.Info("Performing validation that the image is analyzed by Anchore")
	ok, imageObj, err := IsImageAnalyzed(image, "", client, authCtx)
	if err != nil {
		return false, "", err
	}

	if ok {
		return true, fmt.Sprintf("Image %s with digest %s is analyzed", image, imageObj.ImageDigest), nil
	} else {
		return false, fmt.Sprintf("Image %s with digest %s is not analyzed", image, imageObj.ImageDigest), nil
	}
}

func validatePolicy(image string, bundleId string, client *anchore.APIClient, authCtx context.Context) (bool, string, error) {
	log.Info("Performing validation that the image passes policy evaluation in Anchore")
	ok, digest, err := CheckImage(image, "", bundleId, client, authCtx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			return false, fmt.Sprintf("Image %s is not analyzed. Cannot evaluate policy", image), nil
		}
		return false, "", err
	}

	if ok {
		return true, fmt.Sprintf("Image %s with digest %s passed policy checks for policy bundle %s", image, digest, bundleId), nil
	} else {
		return false, fmt.Sprintf("Image %s with digest %s failed policy checks for policy bundle %s", image, digest, bundleId), nil
	}
}

/*
 Analyze an image with optional wait time. If waitTime > 0 the call will block until either a timeout, which returns an error,
 or the analysis completes and the resulting record is returned.

*/
func AnalyzeImage(imageRef string, client *anchore.APIClient, authCtx context.Context) (anchore.AnchoreImage, error) {
	var annotations interface{}

	annotations = map[string]string{
		"requestor": "anchore-admission-controller",
	}

	opts := map[string]interface{}{}

	req := anchore.ImageAnalysisRequest{
		Tag:         imageRef,
		Annotations: &annotations,
		CreatedAt:   time.Now().UTC().Round(time.Second),
	}

	imageList, _, err := client.AnchoreEngineApi.AddImage(authCtx, req, opts)

	if err != nil {
		return anchore.AnchoreImage{}, err
	}

	if len(imageList) == 0 {
		return anchore.AnchoreImage{}, errors.New("No image record received in successful response to image add request")
	}

	return imageList[0], nil

}

func IsImageAnalyzed(imageRef string, optionalDigest string, client *anchore.APIClient, authCtx context.Context) (bool, anchore.AnchoreImage, error) {
	imageObj, err := lookupImage(imageRef, optionalDigest, client, authCtx)
	if err != nil {
		return false, anchore.AnchoreImage{}, err
	} else {
		return imageObj.AnalysisStatus == "analyzed", imageObj, nil
	}
}

func lookupImage(imageRef string, optionalDigest string, client *anchore.APIClient, authCtx context.Context) (anchore.AnchoreImage, error) {
	localOptions := make(map[string]interface{})
	localOptions["fulltag"] = imageRef
	log.Info("Getting image for ref ", imageRef)
	var images anchore.AnchoreImageList
	var err error

	if optionalDigest != "" {
		// Direct lookup with digest
		images, _, err = client.AnchoreEngineApi.GetImage(authCtx, optionalDigest)
	} else {
		// Find latest image with tag
		images, _, err = client.AnchoreEngineApi.ListImages(authCtx, localOptions)
	}

	if err != nil {
		return anchore.AnchoreImage{}, err
	}

	log.Info("Getting image")
	if len(images) == 0 {
		return anchore.AnchoreImage{}, errors.New(fmt.Sprintf("No images found with tag %s", imageRef))
	} else {
		sort.Slice(images, func(i int, j int) bool {
			return images[i].CreatedAt.Before(images[j].CreatedAt)
		})

		return images[0], nil
	}
}

func CheckImage(imageRef string, optionalDigest string, optionalPolicyId string, client *anchore.APIClient, authCtx context.Context) (bool, string, error) {
	var digest string

	if optionalDigest == "" {
		imageObj, err := lookupImage(imageRef, "", client, authCtx)
		if err != nil {
			return false, "", err
		} else {
			digest = imageObj.ImageDigest
		}
	} else {
		digest = optionalDigest
	}

	localOptions := make(map[string]interface{})
	localOptions["interactive"] = true
	if optionalPolicyId != "" {
		localOptions["policyId"] = optionalPolicyId
	}

	evaluations, _, chkErr := client.AnchoreEngineApi.GetImagePolicyCheck(authCtx, digest, imageRef, localOptions)
	if chkErr != nil {
		return false, digest, chkErr
	}

	if len(evaluations) > 0 {
		resultStatus := findResult(evaluations[0])
		return strings.ToLower(resultStatus) == "pass", digest, nil
	} else {
		return false, digest, nil
	}

}

func findResult(parsed_result map[string]map[string][]map[string]interface{}) string {
	//Looks thru a parsed result for the status value, assumes this result is for a single image
	digest := reflect.ValueOf(parsed_result).MapKeys()[0].String()
	tag := reflect.ValueOf(parsed_result[digest]).MapKeys()[0].String()
	status := parsed_result[digest][tag][0]["status"]
	return fmt.Sprintf("%s", status)
}

func initClient(username string, password string, endpoint string) (*anchore.APIClient, context.Context, error) {
	cfg := anchore.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.BasePath = endpoint

	//TODO: cert verification options?
	aClient := anchore.NewAPIClient(cfg)

	//TODO: timeouts
	//ctx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
	auth := context.WithValue(context.Background(), anchore.ContextBasicAuth, anchore.BasicAuth{username, password})
	return aClient, auth, nil
}

func updateConfig(in fsnotify.Event) {
	log.Info("Detected update event to the configuration file. Will reload")
	err := confVpr.ReadInConfig()
	if err != nil {
		log.Error(err, "Error updating configuration")
	}
	err = confVpr.Unmarshal(&config)
	if err != nil {
		log.Error(err, "Error updating configuration")
	}
}

func updateAuthConfig(in fsnotify.Event) {
	log.Info("Detected update event to the configuration file. Will reload")
	err := authVpr.ReadInConfig()
	if err != nil {
		log.Error(err, "Error updating auth configuration")
	}
	err = authVpr.Unmarshal(&authConfig)
	if err != nil {
		log.Error(err, "Error updating auth configuration")
	}
}

func initLogger() {//} (interface{}, error) {
	logz.SetLogger(logz.ZapLogger(false))
	log = logz.Log.WithName("entrypoint")
	//return log, nil
}


func main() {
	initLogger()

	// Hack to fix an issue with log that makes log lines prefixed with: "logging before flag.Parse:". Do not want that
	flag.CommandLine.Parse([]string{})

	// Configure
	log.Info("Initializing configuration")
	configPath, found := os.LookupEnv(configFilePathEnvVar)

	if !found {
		configPath = "/config.json"
	}

	authPath, authFound := os.LookupEnv(credsConfigFilePathEnvVar)
	if !authFound {
		authPath = "/credentials.json"
	}

	log.Info("Loading configuration from ", configPath)
	confVpr = viper.New()
	confVpr.SetConfigFile(configPath)
	err := confVpr.ReadInConfig()
	if err != nil {
		log.Error(err, "Could not load configuration")
		panic(err.Error())
	}

	err = confVpr.Unmarshal(&config)
	if err != nil {
		log.Error(err, "Error unmarshalling configuration")
		panic(err.Error())
	}

	confVpr.OnConfigChange(updateConfig)
	confVpr.WatchConfig()

	log.Info("Loading creds from ", authPath)
	authVpr = viper.New()
	authVpr.SetConfigFile(authPath)
	err2 := authVpr.ReadInConfig()
	if err2 != nil {
		log.Error(err, "Could not load auth configuration")
		panic(err.Error())
	}

	err = authVpr.Unmarshal(&authConfig)
	if err != nil {
		log.Error(err, "Error unmarshalling auth configuration")
		panic(err.Error())
	}
	authVpr.OnConfigChange(updateAuthConfig)
	authVpr.WatchConfig()

	if err != nil {
		log.Error(err, "Cannot initialize the client", err)
		panic(err.Error())
	}

	// creates client with in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Error(err, "Error building in-cluster config for k8s client")
		panic(err.Error())
	}

	// creates the clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Error(err, "Error getting k8s client")
		panic(err.Error())
	}

	log.Info("Starting server")

	// Run the server
	cmd.RunAdmissionServer(&admissionHook{})
}
