/*
The main entry point for the Anchore Kubernetes Admission Controller

This controller, based on the openshift generic admission server, supports both Validating and Mutating Webhooks, configurable via command options

Default behavior is ValidatingAdmissionWebhook-only mode

If the PodSpec has an annotation "breakglass.anchore.com=true" then the image will be allowed regardless of status, thus it is responsibility of the
system admin to ensure the ability of users to add that annotation is restricted as makes sense for that organization


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

	//"github.com/hashicorp/golang-lru"
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

var (
	analysisTimestampAnnotation = "image-analysis.anchore.com/analyzed-timestamp"
	analysisStatusAnnotation    = "image-analysis.anchore.com/analysis-state"
	policyStatusAnnotation      = "policy-evaluation.anchore.com/evaluation-state"
	policyIdAnnotation          = "policy-evaluation.anchore.com/evaluated-policy-id"
)

type admissionHook struct {
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

type ControllerConfiguration struct {
//	Cache     CacheConfiguration
	Validator ValidatorConfiguration
	Mutator   MutatorConfiguration
	Client AnchoreClientConfiguration
}

type CacheConfiguration struct {
	Enabled bool
	Size    int
	Ttl     int
}

type AnchoreClientConfiguration struct {
	Endpoint            string
	Username            string
	Password            string
	VerifyCert          bool
}


type ValidatorConfiguration struct {
	Enabled             bool
	AnalyzeIfNotPresent bool
	AnalyzeTimeout      int
	ValidateStatus      bool //Actually return a validation result based on policy eval status, if false, then the validator returns allowed, but will submit missing images for analysis
}

type MutatorConfiguration struct {
	Enabled        bool
	AnnotationName string
}

type PolicyMappingConfiguration struct {
	Mappings       []RegexMapping
}

type RegexMapping struct {
	SelectorType   string
	Value          string
}

/*
 Does the regex mapping match the candidate
 */
func (m *RegexMapping) matches(imageRef string, annotations map[string]string) (bool, error) {
	return regexp.Match(m.Value, []byte(imageRef))
}

func (pconf *PolicyMappingConfiguration) FindPolicy(imageRef string, annotations map[string]string) (string, error) {
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

//var resultCache *lru.TwoQueueCache

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
	var digest string
	var analyzed bool
	var ok bool
	var imageObj anchore.AnchoreImage
	var err error
	policyId := ""
	var pod v1.Pod
	var containers  []v1.Container
	var statusMsg string

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
			analyzed = false
			analyzed, imageObj, err = IsImageAnalyzed(image, "")
			if err != nil || ! analyzed {
				glog.Info("Did not find analyzed image")
				if config.Validator.AnalyzeIfNotPresent {
					glog.Info("Configured to request analysis on un-analyzed images. Doing so now")

					imgObj, analyzeErr := AnalyzeImage(image, config.Validator.AnalyzeTimeout)
					if analyzeErr != nil {
						glog.Error("Failed analysis, cannot evaluate policy")
					} else {
						digest = imgObj.ImageDigest
					}

				}
			} else {
				glog.Info("Found image for ", image, " already analyzed")
				digest = imageObj.ImageDigest
			}

			if analyzed {
				ok, err = CheckImage(image, digest, policyId)

				if err != nil {
					glog.Error("Error evaluating policy ", policyId, " for image ", image)
					ok = false
				}
			} else {
				ok = false
			}

			status.Allowed, statusMsg = isValid(config.Validator, analyzed, ok)

			if ! status.Allowed {
				msg := fmt.Sprintf("Image %s in PodSpec for container %s failed to pass the policy check for policy %s", image, container.Name, policyId)
				status.Result.Message = statusMsg
				status.Result.Status = metav1.StatusFailure
				glog.Warning(msg)
			} else {
				glog.Info("Image passed policy check: " + image)
			}
		}
	} else {
		glog.Warning("No container specs to validate")
	}

	glog.Info("Returning status: ", status)
	return status
}

func isValid(conf ValidatorConfiguration, isAnalyzed bool, validationOk bool) (bool, string) {
	if conf.ValidateStatus {
		if validationOk {
			return true, "Policy evaluation successful and returned 'passed'"
		} else {
			if ! isAnalyzed {
				return false, "Policy evaluation could not be performed because image has not been analyzed"
			} else {
				return false, "Policy evaluation was successful and returned 'failed'"
			}
		}
	}
	if isAnalyzed {
		return true, "Image is analyzed by Anchore"
	}
	return false, "Image is not analyzed by Anchore, which is required per configuration"
}

/*
 Analyze an image with optional wait time. If waitTime > 0 the call will block until either a timeout, which returns an error,
 or the analysis completes and the resulting record is returned.

 */
func AnalyzeImage(imageRef string, waitTime int) (anchore.AnchoreImage, error) {
	var annotations interface{}
	var digest string
	var img anchore.AnchoreImage
	var result bool

	annotations = map[string]string {
		"AnalysisSource": "anchore-admission-controller",
	}

	opts := map[string]interface{} {}

	req := anchore.ImageAnalysisRequest{
		Tag:         imageRef,
		Annotations: &annotations,
	}

	imageList, _, err := client.AnchoreEngineApi.AddImage(authCtx, req, opts)

	if err != nil {
		return anchore.AnchoreImage{}, err
	} else {
		digest = imageList[0].ImageDigest
	}

	// Wait for the result
	endTime := time.Now().Add(time.Duration(waitTime) * time.Second)

	for time.Now().Before(endTime) {
		if result, img, err = IsImageAnalyzed(imageRef, digest); result && err == nil {
			return img, nil
		}
	}

	return img, errors.New(fmt.Sprintf("Timeout of %d exceeded waiting for analysis to complete", config.Validator.AnalyzeTimeout))

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

func CheckImage(imageRef string, optionalDigest string, optionalPolicyId string) (bool, error) {
	var digest string

	if optionalDigest == "" {
		imageObj, err := lookupImage(imageRef, "")
		if err != nil {
			return false, err
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
		return false, chkErr
	}

	if len(evaluations) > 0 {
		resultStatus := findResult(evaluations[0])
		return strings.ToLower(resultStatus) == "pass", nil
	} else {
		return false, nil
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

	glog.Info(fmt.Sprintf("Configured URL: '%s' from '%s'", cfg.BasePath, conf.Client.Endpoint))

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

func loadConfig(path string) (ControllerConfiguration, error) {
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
	configPath := "/config.json"
	configEnv, found := os.LookupEnv("CONFIG_FILE_PATH")

	if found {
		configPath = configEnv
	}

	var err error
	config, err = loadConfig(configPath)
	if err != nil {
		glog.Fatal("Could not load configuration from ", configPath)
		os.Exit(1)
	}

	err = InitializeClient(config)
	if err != nil {
		glog.Fatal("Cannot initialize the client", err)
		os.Exit(1)
	}

	//resultCache, err = lru.New2Q(1024)

	if err != nil {
		glog.Fatal("Cannot initialize the cache")
		os.Exit(1)
	}

	glog.Info("Starting server")

	// Run the server
	cmd.RunAdmissionServer(&admissionHook{})
}
