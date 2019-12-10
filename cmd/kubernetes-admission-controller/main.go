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
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
	"github.com/antihax/optional"
	"github.com/fsnotify/fsnotify"
	"github.com/openshift/generic-admission-server/pkg/cmd"
	"github.com/spf13/viper"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

var authVpr *viper.Viper
var confVpr *viper.Viper
var config ControllerConfiguration
var authConfig AnchoreAuthConfig

//var log logr.Logger

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
				klog.Error("Error evaluating regexp key= ", k, " regex = ", selector.SelectorKeyRegex, " err=", err)
				match = false
			}

			match2, err := regexp.MatchString(selector.SelectorValueRegex, v)
			if err != nil {
				klog.Error("Error evaluating regexp ", " value = ", v, " regex = ", selector.SelectorValueRegex, " err=", err)
				match2 = false

			}

			if match && match2 {
				return true, nil
			}

		}
	}

	// Treat Name specially
	if strings.ToLower(selector.SelectorKeyRegex) == "name" {
		match, err := regexp.MatchString(selector.SelectorValueRegex, objMeta.Name)
		if err != nil {
			klog.Error("Failed evaluating regex against metadata Name entry = ", objMeta.Name, " regex = ", selector.SelectorValueRegex, " err=", err)
			match = false
		}

		if match {
			return true, nil
		}

	}

	return false, nil
}

/*
  Match the image reference itself (tag)
*/
func matchImageResource(regex string, img string) (bool, error) {
	matches, err := regexp.MatchString(regex, img)
	return matches, err
}

/*
  Get the correct set of ObjectMeta for comparison, or nil if not a selector that uses ObjectMeta
*/
func resolveResource(selector *ResourceSelector, pod *v1.Pod) (*metav1.ObjectMeta, error) {
	klog.Info("Resolving the resource to use for selection")

	switch selector.ResourceType {
	case PodSelectorType:
		return &pod.ObjectMeta, nil
	case NamespaceSelectorType:
		nsFound, err := clientset.CoreV1().Namespaces().Get(pod.Namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		} else {
			return &nsFound.ObjectMeta, nil
		}
	case ImageSelectorType:
		return nil, nil
	default:
		return nil, nil
	}
}

func (a *admissionHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("Initializing handler")

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
	var mode GateModeType
	var imageDigest string

	matched := false

	status := &admissionv1beta1.AdmissionResponse{
		Allowed: true,
		UID:     admissionSpec.UID,
		Result:  &metav1.Status{Status: metav1.StatusSuccess, Message: ""}}

	// Handle higher-level types as well as pods, helps make error messages cleaner
	if strings.ToLower(admissionSpec.Kind.Kind) != "pod" {
		klog.Info("Non-pod validation requested. No validation to do")
		return status
	}

	klog.Info("Handling a Pod validation")
	err = json.Unmarshal(admissionSpec.Object.Raw, &pod)
	if err != nil {
		klog.Error("Could not parse the pod spec err=", err)
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
			matched = false
			imageDigest = ""
			image := container.Image
			klog.Info("Evaluating selectors for image=", image)

			policyRef = nil

			for _, selector := range config.PolicySelectors {
				klog.Info("Checking selector ", "selector=", selector)
				meta, err := resolveResource(&selector.Selector, &pod)
				if err != nil {
					klog.Error("Error checking selector, skipping err=", err)
					continue
				}

				if meta != nil {
					if match, err := matchObjMetadata(&selector.Selector, meta); match {
						if err != nil {
							klog.Error("Error doing selector match on metadata err=", err)
							continue
						}

						policyRef = &selector.PolicyReference
						mode = selector.Mode
						matched = true
						klog.Info("Matched selector rule=", selector)
						break
					}
				} else {
					if match, err := matchImageResource(selector.Selector.SelectorValueRegex, image); match {
						if err != nil {
							klog.Error("Error doing selector match on image reference err=", err)
							continue
						}
						policyRef = &selector.PolicyReference
						mode = selector.Mode
						matched = true
						klog.Info("Matched selector rule=", selector, " with mode=", mode)
						break
					}
				}
			}

			if !matched {
				// No rule matched, so skip this image
				klog.Info("No selector match found")
				break
			}

			anchoreClient = nil
			authCtx = nil

			if policyRef != nil {
				for _, entry := range authConfig.Users {
					if entry.Username == policyRef.Username {
						klog.Info("Found selector match for user ", "Username=", entry.Username, " PolicyBundleId=", policyRef.PolicyBundleId)
						anchoreClient, authCtx, _ = initClient(entry.Username, entry.Password, config.AnchoreEndpoint)
					}
				}
			}

			if mode == PolicyGateMode {
				if anchoreClient == nil || authCtx == nil || policyRef == nil {
					klog.Error("No valid policy reference with valid credentials found. Failing validation")
					status.Allowed = false
					status.Result.Status = metav1.StatusFailure
					status.Result.Reason = "No policy/endpoint selector matched the request or no client credentials were available, but the validator configuration requires it"
					break
				}

				status.Allowed, imageDigest, status.Result.Message, err = validatePolicy(image, policyRef.PolicyBundleId, anchoreClient, authCtx)

			} else if mode == AnalysisGateMode {
				if anchoreClient == nil || authCtx == nil {
					klog.Error("No valid policy reference with valid credentials found. Failing validation")
					status.Allowed = false
					status.Result.Status = metav1.StatusFailure
					status.Result.Reason = "No policy/endpoint selector matched the request or no client credentials were available, but the validator configuration requires it"
					break
				}

				status.Allowed, imageDigest, status.Result.Message, err = validateAnalyzed(image, anchoreClient, authCtx)

			} else if mode == BreakGlassMode {
				klog.Info("No check requirements in config and no analysis request configured. Allowing")
				status.Allowed = true
			} else {
				klog.Error("Got unexpected mode value for matching selector. Failing on error. Mode=", mode)
				status.Allowed = false
				status.Result.Status = metav1.StatusFailure
				status.Result.Message = "Invalid controller configuration encountered. Could not execute check correctly"
				break
			}

			// Only request analysis if the other gates failed, indicating either missing image or policy failure
			if imageDigest == "" && config.Validator.RequestAnalysis {
				if anchoreClient == nil || authCtx == nil {
					klog.Error("Image analysis request configured but no credentials mapped to execute the call. Skipping")
				} else {
					klog.Info("Requesting analysis of image ", "image=", image)
					_, _, err = passiveValidate(image, anchoreClient, authCtx)
					if err != nil {
						klog.Error("Error requesting analysis of image, but ignoring for validation result. err=", err)
					}
				}
			} else {
				klog.Info("Skipping analysis request")
			}

			if !status.Allowed {
				status.Result.Status = metav1.StatusFailure
				if err != nil && status.Result.Message == "" {
					status.Result.Message = err.Error()
				}
				//Break on the first disallowed image if there are multiple
				break
			}
		}
	} else {
		klog.Info("No container specs to validate")
	}

	klog.Info("Returning status=", status)
	return status
}

func passiveValidate(image string, client *anchore.APIClient, authCtx context.Context) (bool, string, error) {
	klog.Info("Performing passive validation. Will request image analysis and always allow admission")
	var err error

	imgObj, err := AnalyzeImage(image, client, authCtx)
	if err != nil {
		klog.Error("Error from analysis request err=", err)
		return true, "Allowed but could not request analysis due to error", nil
	}

	return true, fmt.Sprintf("Image analysis for image %s requested and found mapped to digest %s", image, imgObj.ImageDigest), nil
}

// Returns bool is analyzed, string digest, string message, and error
func validateAnalyzed(image string, client *anchore.APIClient, authCtx context.Context) (bool, string, string, error) {

	klog.Info("Performing validation that the image is analyzed by Anchore")
	ok, imageObj, err := IsImageAnalyzed(image, "", client, authCtx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			klog.Info("Image is not analyzed")
			return false, "", fmt.Sprintf("Image %s is not analyzed.", image), nil
		} else {
			klog.Error("Error checking anchore for image analysis status: err=", err)
			return false, "", "", err
		}
	}

	if ok {
		klog.Info("Image is analyzed")
		return true, imageObj.ImageDigest, fmt.Sprintf("Image %s with digest %s is analyzed", image, imageObj.ImageDigest), nil
	} else {
		klog.Info("Image is not analyzed")
		return false, imageObj.ImageDigest, fmt.Sprintf("Image %s with digest %s is not analyzed", image, imageObj.ImageDigest), nil
	}
}

// Returns bool is passed policy, string digest, string message, and error
func validatePolicy(image string, bundleId string, client *anchore.APIClient, authCtx context.Context) (bool, string, string, error) {
	klog.Info("Performing validation that the image passes policy evaluation in Anchore")
	ok, digest, err := CheckImage(image, "", bundleId, client, authCtx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			klog.Info("Image is not analyzed, cannot evaluate policy")
			return false, "", fmt.Sprintf("Image %s is not analyzed. Cannot evaluate policy", image), nil
		}
		klog.Error("Image is not analyzed, error during evaluation check. err=", err)
		return false, digest, "", err
	}

	if ok {
		klog.Info("Image passed policy evaluation. image=", image)
		return true, digest, fmt.Sprintf("Image %s with digest %s passed policy checks for policy bundle %s", image, digest, bundleId), nil
	} else {
		klog.Info("Image failed policy evaluation. image=", image)
		return false, digest, fmt.Sprintf("Image %s with digest %s failed policy checks for policy bundle %s", image, digest, bundleId), nil
	}
}

/*
 Analyze an image with optional wait time. If waitTime > 0 the call will block until either a timeout, which returns an error,
 or the analysis completes and the resulting record is returned.

*/
func AnalyzeImage(imageRef string, client *anchore.APIClient, authCtx context.Context) (anchore.AnchoreImage, error) {

	annotations := make(map[string]interface{})
	annotations["requestor"] = "anchore-admission-controller"

	opts := anchore.AddImageOpts{}
	opts.Autosubscribe = optional.NewBool(false)

	req := anchore.ImageAnalysisRequest{
		Tag:         imageRef,
		Annotations: annotations,
		CreatedAt:   time.Now().UTC().Round(time.Second),
	}

	imageList, _, err := client.ImagesApi.AddImage(authCtx, req, &opts)

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
		isAnalyzed := imageObj.AnalysisStatus == "analyzed"
		klog.Info("Image analyzed = ", isAnalyzed)
		return isAnalyzed, imageObj, nil
	}
}

func lookupImage(imageRef string, optionalDigest string, client *anchore.APIClient, authCtx context.Context) (anchore.AnchoreImage, error) {
	localOptions := anchore.ListImagesOpts{}
	localOptions.Fulltag = optional.NewString(imageRef)
	klog.Info("Getting image from anchore engine. Reference=", imageRef)
	var images []anchore.AnchoreImage
	var err error

	if optionalDigest != "" {
		// Direct lookup with digest
		images, _, err = client.ImagesApi.GetImage(authCtx, optionalDigest, &anchore.GetImageOpts{})
	} else {
		// Find latest image with tag
		images, _, err = client.ImagesApi.ListImages(authCtx, &localOptions)
	}

	if err != nil {
		return anchore.AnchoreImage{}, err
	}

	klog.Info("Getting image")
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

	localOptions := anchore.GetImagePolicyCheckOpts{}
	localOptions.Interactive = optional.NewBool(true)
	if optionalPolicyId != "" {
		localOptions.PolicyId = optional.NewString(optionalPolicyId)
	}

	evaluations, _, chkErr := client.ImagesApi.GetImagePolicyCheck(authCtx, digest, imageRef, &localOptions)
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

func findResult(parsed_result map[string]interface{}) string {
	// Looks thru a parsed result for the status value, assumes this result is for a single image
	digest := reflect.ValueOf(parsed_result).MapKeys()[0].String()
	tag := reflect.ValueOf(parsed_result[digest]).MapKeys()[0]
	result := reflect.ValueOf(reflect.ValueOf(parsed_result[digest]).MapIndex(tag).Interface()).Index(0).Elem()
	for _, key := range result.MapKeys() {
		if key.Interface() == "status" {
			status := result.MapIndex(key)
			return fmt.Sprintf("%s", status)
		}
	}

	return fmt.Sprintf("%s", "failed to get status")
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
	klog.Info("Detected update event to the configuration file. Will reload")
	err := confVpr.ReadInConfig()
	if err != nil {
		klog.Error("Error updating configuration. err=", err)
	}
	err = confVpr.Unmarshal(&config)
	if err != nil {
		klog.Error("Error updating configuration. err=", err)
	}
}

func updateAuthConfig(in fsnotify.Event) {
	klog.Info("Detected update event to the configuration file. Will reload")
	err := authVpr.ReadInConfig()
	if err != nil {
		klog.Error("Error updating auth configuration. err=", err)
	}
	err = authVpr.Unmarshal(&authConfig)
	if err != nil {
		klog.Error("Error updating auth configuration. err=", err)
	}
}

// For use later to switch to the controller runtime structured logging
//func initLogger() (interface{}, error) {
//	logz.SetLogger(logz.ZapLogger(false))
//	log = logz.log.WithName("entrypoint")
//	return log, nil
//}

func main() {
	//initLogger()

	// Hack to fix an issue with log that makes log lines prefixed with: "logging before flag.Parse:". Do not want that
	flag.CommandLine.Parse([]string{})

	// Configure
	klog.Info("Initializing configuration")
	configPath, found := os.LookupEnv(configFilePathEnvVar)

	if !found {
		configPath = "/config.json"
	}

	authPath, authFound := os.LookupEnv(credsConfigFilePathEnvVar)
	if !authFound {
		authPath = "/credentials.json"
	}

	klog.Info("Loading configuration from ", configPath)
	confVpr = viper.New()
	confVpr.SetConfigFile(configPath)
	err := confVpr.ReadInConfig()
	if err != nil {
		klog.Error("Could not load configuration err=", err)
		panic(err.Error())
	}

	err = confVpr.Unmarshal(&config)
	if err != nil {
		klog.Error("Error unmarshalling configuration err=", err)
		panic(err.Error())
	}

	confVpr.OnConfigChange(updateConfig)
	confVpr.WatchConfig()

	klog.Info("Loading creds from ", authPath)
	authVpr = viper.New()
	authVpr.SetConfigFile(authPath)
	err = authVpr.ReadInConfig()
	if err != nil {
		klog.Error("Could not load auth configuration err=", err)
		panic(err.Error())
	}

	err = authVpr.Unmarshal(&authConfig)
	if err != nil {
		klog.Error("Error unmarshalling auth configuration err=", err)
		panic(err.Error())
	}
	authVpr.OnConfigChange(updateAuthConfig)
	authVpr.WatchConfig()

	if err != nil {
		klog.Error("Cannot initialize the client err=", err)
		panic(err.Error())
	}

	// creates client with in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Error("Error building in-cluster config for k8s client err=", err)
		panic(err.Error())
	}

	// creates the clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		klog.Error("Error getting k8s client err=", err)
		panic(err.Error())
	}

	klog.Info("Starting server")

	// Run the server
	cmd.RunAdmissionServer(&admissionHook{})
}
