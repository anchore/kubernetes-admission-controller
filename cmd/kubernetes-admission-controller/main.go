/*
The main entry point for the Anchore Kubernetes Admission Controller

This controller, based on the openshift generic admission server), supports Validating Webhook requests

Default behavior is ValidatingAdmissionWebhook-only mode

 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
	"github.com/golang/glog"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/openshift/generic-admission-server/pkg/cmd"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"os"
	"regexp"
	"sort"
	"sync"
)

var config ControllerConfiguration
var client *anchore.APIClient
var authCtx context.Context

type admissionHook struct {
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

type ControllerConfiguration struct {
	Validator ValidatorConfiguration
	// TODO: for adding mutating support
	//Mutator   MutatorConfiguration
	Client AnchoreClientConfiguration
}

type AnchoreClientConfiguration struct {
	Endpoint            string
	Username            string
	Password            string
	PolicyBundle        string
	//VerifyCert          bool
}

type ValidatorConfiguration struct {
	Enabled             bool
	RequireImageAnalyzed bool
	RequirePassPolicy   bool
	RequestAnalysis     bool
}

type PolicyMappingConfiguration struct {
	Mappings       []RegexMapping
}

type RegexMapping struct {
	SelectorType   MatchSelector
	Value          string
}

type MatchSelector string
const (
	MatchLabel MatchSelector = "label"
	MatchAnnotation MatchSelector = "annotation"
	MatchAny MatchSelector = "any"
	)

/*
 Does the regex mapping match the candidate
 */
func (m *RegexMapping) matches(imageRef string, annotations map[string]string) (bool, error) {
	return regexp.Match(m.Value, []byte(imageRef))
}

func (pconf *PolicyMappingConfiguration) FindPolicy(imageRef string, annotations map[string]string, labels map[string]string) (string, error) {
	for _, mapping := range pconf.Mappings {
		if v, err := mapping.matches(imageRef, annotations); err != nil {
			if v {
				return mapping.Value, nil
			}
		} else {
			return "", err
		}
	}
	return "", nil
}

func (a *admissionHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	glog.Info("Initializing handler")

	return nil
}

func (a *admissionHook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	return schema.GroupVersionResource{
		Group:    "admission.anchore.io",
		Version:  "v1beta1",
		Resource: "imagechecks",
	},"imagecheck"

}

func (a *admissionHook) Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	var err error
	var pod v1.Pod
	var containers  []v1.Container

	status := &admissionv1beta1.AdmissionResponse{
		Allowed: true,
		UID:     admissionSpec.UID,
		Result:  &metav1.Status{Status: metav1.StatusSuccess, Message: ""}}

	// Handle higher-level types as well as pods, helps make error messages cleaner
	if strings.ToLower(admissionSpec.Kind.Kind) == "pod" {
		glog.Info("Handling a Pod validation")
		err = json.Unmarshal(admissionSpec.Object.Raw, &pod)
		if err != nil {
			glog.Error("Could not parse the pod spec", err)
			status.Allowed = false
			status.Result.Status = metav1.StatusFailure
			status.Result.Reason = "Error parsing admission request pod spec"
			return status
		}
		containers = pod.Spec.Containers
	}

	if containers != nil && len(containers) > 0 {
		for _, container := range containers {
			image := container.Image
			glog.Info("Checking image: " + image)

			if config.Validator.RequirePassPolicy {
				status.Allowed, status.Result.Message, err = validatePolicy(image, config)

				// If configured, do the analysis, but do not wait and do not change admission result
				if err != nil && config.Validator.RequestAnalysis {
					_, err2 := AnalyzeImage(image)
					if err2 != nil {
						glog.Warning("During requested image analysis submission, an error occurred: ", err2)
					}
				}
			} else if config.Validator.RequireImageAnalyzed {
				status.Allowed, status.Result.Message, err = validateAnalyzed(image, config)

				// If configured, do the analysis, but do not wait and do not change admission result
				if err != nil && config.Validator.RequestAnalysis {
					_, err2 := AnalyzeImage(image)
					if err2 != nil {
						glog.Warning("During requested image analysis submission, an error occurred: ", err2)
					}
				}
			} else if config.Validator.RequestAnalysis {
				status.Allowed, status.Result.Message, err = passiveValidate(image, config)
			} else {
				glog.Info("No check requirements in config and no analysis request configured. Allowing")
				status.Allowed = true
			}

			if ! status.Allowed {
				status.Result.Status = metav1.StatusFailure
				if err != nil {
					status.Result.Message = err.Error()
				}
			}
		}
	} else {
		glog.Warning("No container specs to validate")
	}

	glog.Info("Returning status: ", status)
	return status
}

func passiveValidate(image string, conf ControllerConfiguration) (bool, string, error) {
	glog.Info("Performing passive validation. Will request image analysis and always allow admission")

	imgObj, err := AnalyzeImage(image)
	if err != nil {
		glog.Error("Error from analysis request", err.Error())
		return true, "Allowed but could not request analysis due to error", nil
	}

	return true, fmt.Sprintf("Image analysis for image %s requested and found mapped to digest %s", image, imgObj.ImageDigest), nil
}

func validateAnalyzed(image string, conf ControllerConfiguration) (bool, string, error) {
	glog.Info("Performing validation that the image is analyzed by Anchore")
	ok, imageObj, err := IsImageAnalyzed(image, "")
	if err != nil {
		return false, "", err
	}

	if ok {
		return true, fmt.Sprintf("Image %s with digest %s is analyzed", image, imageObj.ImageDigest), nil
	} else {
		return false, fmt.Sprintf("Image %s with digest %s is not analyzed", image, imageObj.ImageDigest), nil
	}
}

func validatePolicy(image string, conf ControllerConfiguration) (bool, string, error) {
	glog.Info("Performing validation that the image passes policy evaluation in Anchore")
	ok, digest, err := CheckImage(image, "", config.Client.PolicyBundle)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			return false, fmt.Sprintf("Image %s is not analyzed. Cannot evaluate policy", image), nil
		}
		return false, "", err
	}

	if ok {
		return true, fmt.Sprintf("Image %s with digest %s passed policy checks for policy bundle %s", image, digest, conf.Client.PolicyBundle), nil
	} else {
		return false, fmt.Sprintf("Image %s with digest %s failed policy checks for policy bundle %s", image, digest, conf.Client.PolicyBundle), nil
	}
}

/*
 Analyze an image with optional wait time. If waitTime > 0 the call will block until either a timeout, which returns an error,
 or the analysis completes and the resulting record is returned.

 */
func AnalyzeImage(imageRef string) (anchore.AnchoreImage, error) {
	var annotations interface{}

	annotations = map[string]string {
		"requestor": "anchore-admission-controller",
	}

	opts := map[string]interface{} {}

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

func IsImageAnalyzed(imageRef string, optionalDigest string) (bool, anchore.AnchoreImage, error) {
	imageObj, err := lookupImage(imageRef, optionalDigest)
	if err != nil {
		return false, anchore.AnchoreImage{}, err
	} else {
		return imageObj.AnalysisStatus == "analyzed", imageObj, nil
	}
}

func lookupImage(imageRef string, optionalDigest string) (anchore.AnchoreImage, error) {
	localOptions := make(map[string]interface{})
	localOptions["fulltag"] = imageRef
	glog.Info("Getting image for ref ", imageRef)
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

	glog.Info("Getting image")
	if len(images) == 0 {
		return anchore.AnchoreImage{}, errors.New(fmt.Sprintf("No images found with tag %s", imageRef))
	} else {
		sort.Slice(images, func(i int, j int) bool {
			return images[i].CreatedAt.Before(images[j].CreatedAt)
		})

		return images[0], nil
	}
}

func CheckImage(imageRef string, optionalDigest string, optionalPolicyId string) (bool, string, error) {
	var digest string

	if optionalDigest == "" {
		imageObj, err := lookupImage(imageRef, "")
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

	evaluations, _, chkErr:= client.AnchoreEngineApi.GetImagePolicyCheck(authCtx, digest, imageRef, localOptions)
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

func initClient(conf ControllerConfiguration) (*anchore.APIClient, context.Context, error) {
	cfg := anchore.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.BasePath = conf.Client.Endpoint

	//if ! conf.Client.VerifyCert {
	//	// TODO
	//}

	aClient := anchore.NewAPIClient(cfg)
	//ctx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
	auth := context.WithValue(context.Background(), anchore.ContextBasicAuth, anchore.BasicAuth{conf.Client.Username, conf.Client.Password})
	return aClient, auth, nil
}

func InitializeClient(conf ControllerConfiguration) error {
	var err error
	client, authCtx, err = initClient(conf)
	return err
}

func loadConfig(path string, envUsername string, envPassword string) (ControllerConfiguration, error) {
	var conf ControllerConfiguration

	if fd, err := os.Open(path); err == nil {
		defer fd.Close()

		buff, err := ioutil.ReadAll(fd)
		if err != nil {
			glog.Error("Could not read config from file ", path, ". Error: ", err)
			return conf, err
		}

		if err = json.Unmarshal(buff, &conf); err == nil {
			glog.Info("Loaded configuration")
		} else {
			glog.Fatal("Could not unmarshal the config json: ", err)
			return conf, err
		}

		if envUsername != "" {
			conf.Client.Username = envUsername
		}

		if envPassword != "" {
			conf.Client.Password = envPassword
		}

		return conf, nil
	} else {
		glog.Fatal("Cannot load configuration: ", err)
		return conf, err
	}
}

func main() {
	// Hack to fix an issue with glog that makes log lines prefixed with: "logging before flag.Parse:". Do not want that
	flag.CommandLine.Parse([]string{})

	// Configure
	glog.Info("Initializing configuration")
	configPath, found := os.LookupEnv("CONFIG_FILE_PATH")

	envUsr, usrFound := os.LookupEnv("ANCHORE_USERNAME")
	envPassword, passFound := os.LookupEnv("ANCHORE_PASSWORD")

	if ! usrFound {
		envUsr = ""
	}
	if ! passFound {
		envPassword = ""
	}

	if ! found {
		configPath = "/config.json"
	}

	var err error
	config, err = loadConfig(configPath, envUsr, envPassword)
	if err != nil {
		glog.Fatal("Could not load configuration from ", configPath)
		os.Exit(1)
	}

	err = InitializeClient(config)

	if err != nil {
		glog.Fatal("Cannot initialize the client", err)
		os.Exit(1)
	}

	glog.Info("Starting server with URL: ", config.Client.Endpoint, " and config: ", config.Validator)
	if config.Client.PolicyBundle != "" {
		glog.Info("Using policy bundle: ", config.Client.PolicyBundle)
	}

	// Run the server
	cmd.RunAdmissionServer(&admissionHook{})
}
