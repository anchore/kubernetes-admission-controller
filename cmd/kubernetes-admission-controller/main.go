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
	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
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

// The handler map to route based on the admission kind
var resourceHandlers = map[string]func(v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error){
	metav1.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "Pod",
	}.String(): podHandler,
	metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	}.String(): deploymentPodExtractor,
}

/*
Get the PodSpecs and ObjectMeta from a Pod resource
*/
func podHandler(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var pod v1.Pod
	err := json.Unmarshal(admissionRequest.Object.Raw, &pod)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}
	return pod.ObjectMeta, []v1.PodSpec{pod.Spec}, nil
}

/*
Get the PodSpecs and ObjectMeta from a Deployment resource
*/
func deploymentPodExtractor(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	// Extracts pod specs from the deployment resource
	var deployment appsV1.Deployment
	err := json.Unmarshal(admissionRequest.Object.Raw, &deployment)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return deployment.ObjectMeta, []v1.PodSpec{deployment.Spec.Template.Spec}, nil
}

func doesKeyValuePairMatchResourceSelector(key, value string,
	resourceSelector ResourceSelector) bool {
	doesMatch, err := regexp.MatchString(resourceSelector.SelectorKeyRegex, key)
	if err != nil {
		klog.Error("Error evaluating regexp key= ", key, " regex = ", resourceSelector.SelectorKeyRegex, " err=", err)
	}
	if !doesMatch {
		return false
	}

	doesMatch, err = regexp.MatchString(resourceSelector.SelectorValueRegex, value)
	if err != nil {
		klog.Error("Error evaluating regexp ", " value = ", value, " regex = ", resourceSelector.SelectorValueRegex,
			" err=", err)
	}
	return doesMatch
}

/*
  Match any object metadata to the selector
*/
func doesObjectMatchResourceSelector(object *metav1.ObjectMeta, resourceSelector ResourceSelector) bool {
	mapArray := []map[string]string{object.Labels, object.Annotations}
	for _, kvMap := range mapArray {
		for k, v := range kvMap {
			if doesKeyValuePairMatchResourceSelector(k, v, resourceSelector) {
				return true
			}
		}
	}

	// Treat Name specially
	if strings.ToLower(resourceSelector.SelectorKeyRegex) == "name" {
		doesSelectorMatchName, err := regexp.MatchString(resourceSelector.SelectorValueRegex, object.Name)
		if err != nil {
			klog.Error("Failed evaluating regex against metadata Name entry = ", object.Name, " regex = ", resourceSelector.SelectorValueRegex, " err=", err)
		}
		return doesSelectorMatchName
	}

	return false
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
func selectObjectMetaForMatching(selector ResourceSelector, objectMeta metav1.ObjectMeta) (*metav1.ObjectMeta, error) {
	klog.Info("Resolving the resource to use for selection")
	switch selector.ResourceType {
	case ResourceSelectorType:
		return &objectMeta, nil
	case NamespaceSelectorType:
		nsFound, err := clientset.CoreV1().Namespaces().Get(objectMeta.Namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		return &nsFound.ObjectMeta, nil
	case ImageSelectorType:
		return nil, nil
	default:
		return nil, nil
	}
}

func (a *admissionHook) Initialize(*rest.Config, <-chan struct{}) error {
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

func defaultAdmissionResponse(request v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	return successAdmissionResponse(request, "")
}

func successAdmissionResponse(request v1beta1.AdmissionRequest, reason string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		UID:     request.UID,
		Result: &metav1.Status{
			Status:  metav1.StatusSuccess,
			Message: "",
			Reason:  metav1.StatusReason(reason),
		},
	}
}

func errorAdmissionResponse(request v1beta1.AdmissionRequest, message string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: false,
		UID:     request.UID,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: message,
		},
	}
}

func (a *admissionHook) Validate(admissionRequest *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	if admissionRequest == nil {
		return nil
	}
	request := *admissionRequest

	status := &v1beta1.AdmissionResponse{
		Allowed: true,
		UID:     request.UID,
		Result:  &metav1.Status{Status: metav1.StatusSuccess, Message: ""},
	}

	// Handle higher-level types as well as pods, helps make error messages cleaner
	handler, _ := resourceHandlers[request.Kind.String()]
	if handler == nil {
		klog.Error("unsupported admission request kind ", request.Kind.Kind)
		return defaultAdmissionResponse(request)
	}

	// Use the handler to get podSpec from the appropriate resource handler
	objectMeta, podSpecs, err := handler(request)
	if err != nil {
		klog.Error("could not handle the admission request err=", err)
		return errorAdmissionResponse(request, "Error parsing admission request to extract object kind and metadata")
	}

	if len(podSpecs) == 0 {
		klog.Info("No pod spec found in resource. Nothing to validate")
		return successAdmissionResponse(request, "no pod spec or images found to validate")
	}

	// TODO: this should be e loop to handle types with multiple pod specs
	podSpec := podSpecs[0]
	containers := podSpec.Containers

	if len(containers) == 0 {
		klog.Info("No container specs to validate")
		return defaultAdmissionResponse(request)
	}

	for _, container := range containers {
		image := container.Image
		klog.Info("Evaluating selectors for image=", image)

		gateConfiguration := getMatchingGateConfiguration(objectMeta, image)

		if gateConfiguration == nil {
			// No rule matched, so skip this image
			klog.Info("No selector match found")
			continue
		}

		var anchoreClient anchoreImagesClient = nil
		var authCtx context.Context = nil

		for _, entry := range authConfig.Users {
			if entry.Username == gateConfiguration.PolicyReference.Username {
				klog.Info("Found selector match for user ", "Username=", entry.Username, " PolicyBundleId=", gateConfiguration.PolicyReference.PolicyBundleId)
				anchoreClient, authCtx, _ = initClient(entry.Username, entry.Password, config.AnchoreEndpoint)
			}
		}

		var imageDigest string

		// TODO: defer an analysis request —— only if no Anchore image, we have creds,
		//  and `config.Validator.RequestAnalysis` is true

		// TODO: then, we can immediately return admissionResponses from validate* functions

		mode := gateConfiguration.Mode
		policyReference := gateConfiguration.PolicyReference

		switch gateConfiguration.Mode {
		case PolicyGateMode:
			if anchoreClient == nil || authCtx == nil {
				klog.Error("No valid policy reference with valid credentials found. Failing validation")
				return errorAdmissionResponse(request, "No policy/endpoint selector matched the request or no client credentials were available, but the validator configuration requires it")
			}

			status.Allowed, imageDigest, status.Result.Message, err = validatePolicy(image, policyReference.PolicyBundleId, anchoreClient, authCtx)

		case AnalysisGateMode:
			if anchoreClient == nil || authCtx == nil {
				klog.Error("No valid policy reference with valid credentials found. Failing validation")
				return errorAdmissionResponse(request, "No policy/endpoint selector matched the request or no client credentials were available, but the validator configuration requires it")
			}

			status.Allowed, imageDigest, status.Result.Message, err = validateAnalyzed(image, anchoreClient, authCtx)

		case BreakGlassMode:
			klog.Info("No check requirements in config and no analysis request configured. Allowing")
			return defaultAdmissionResponse(request)

		default:
			klog.Error("Got unexpected mode value for matching selector. Failing on error. Mode=", mode)
			return errorAdmissionResponse(request, "Invalid controller configuration encountered. Could not execute check correctly")
		}

		// Only request analysis if the other gates failed, indicating either missing image or policy failure
		if imageDigest != "" || !config.Validator.RequestAnalysis {
			klog.Info("Skipping analysis request")
		} else if anchoreClient == nil || authCtx == nil {
			klog.Error("Image analysis request configured but no credentials mapped to execute the call. Skipping")
		} else {
			klog.Info("Requesting analysis of image ", "image=", image)
			err = requestAnalysis(image, anchoreClient, authCtx)
			if err != nil {
				klog.Error("Error requesting analysis of image, but ignoring for validation result. err=", err)
			}
		}

		if !status.Allowed {
			message := status.Result.Message
			if err != nil && status.Result.Message == "" {
				message = err.Error()
			}

			return errorAdmissionResponse(request, message)
		}
	}

	response := defaultAdmissionResponse(request)
	klog.Info("Returning status=", response)
	return response
}

func getMatchingGateConfiguration(objectMeta metav1.ObjectMeta, image string) *GateConfiguration {
	for _, policySelector := range config.PolicySelectors {
		klog.Info("Checking selector ", "selector=", policySelector)

		meta, err := selectObjectMetaForMatching(policySelector.ResourceSelector, objectMeta)
		if err != nil {
			klog.Error("Error checking selector, skipping err=", err)
			continue
		}

		if meta != nil {
			if match := doesObjectMatchResourceSelector(meta, policySelector.ResourceSelector); match {
				klog.Info("Matched selector rule=", policySelector)

				return &GateConfiguration{
					Mode:            policySelector.Mode,
					PolicyReference: policySelector.PolicyReference,
				}
			}
		} else {
			if match, err := matchImageResource(policySelector.ResourceSelector.SelectorValueRegex, image); match {
				if err != nil {
					klog.Error("Error doing selector match on image reference err=", err)
					continue
				}

				klog.Info("Matched selector rule=", policySelector, " with mode=", policySelector.Mode)

				return &GateConfiguration{
					Mode:            policySelector.Mode,
					PolicyReference: policySelector.PolicyReference,
				}
			}
		}
	}

	return nil
}

func requestAnalysis(image string, client anchoreImagesClient, authCtx context.Context) error {
	klog.Info("Performing passive validation. Will request image analysis")

	anchoreImage, err := analyzeImage(image, client, authCtx)
	if err != nil {
		klog.Error("Error from analysis request err=", err)
		return fmt.Errorf("error requesting analysis: %w", err)
	}

	klog.Info(fmt.Sprintf("Image analysis for image %s requested and found mapped to digest %s", image, anchoreImage.ImageDigest))
	return nil
}

// Returns bool is analyzed, string digest, string message, and error
func validateAnalyzed(image string, client anchoreImagesClient, authCtx context.Context) (bool, string, string, error) {
	klog.Info("Performing validation that the image is analyzed by Anchore")
	ok, imageObj, err := isImageAnalyzed(image, client, authCtx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			klog.Info("Image is not analyzed")
			return false, "", fmt.Sprintf("Image %s is not analyzed.", image), nil
		}

		klog.Error("Error checking anchore for image analysis status: err=", err)
		return false, "", "", err
	}

	if ok {
		klog.Info("Image is analyzed")
		return true, imageObj.ImageDigest, fmt.Sprintf("Image %s with digest %s is analyzed", image, imageObj.ImageDigest), nil
	}

	klog.Info("Image is not analyzed")
	return false, imageObj.ImageDigest, fmt.Sprintf("Image %s with digest %s is not analyzed", image, imageObj.ImageDigest), nil
}

// Returns bool is passed policy, string digest, string message, and error
func validatePolicy(image string, bundleId string, client anchoreImagesClient, authCtx context.Context) (bool, string, string, error) {
	klog.Info("Performing validation that the image passes policy evaluation in Anchore")
	ok, digest, err := CheckImage(image, bundleId, client, authCtx)
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
	}

	klog.Info("Image failed policy evaluation. image=", image)
	return false, digest, fmt.Sprintf("Image %s with digest %s failed policy checks for policy bundle %s", image, digest, bundleId), nil
}

/*
 Analyze an image with optional wait time. If waitTime > 0 the call will block until either a timeout, which returns an error,
 or the analysis completes and the resulting record is returned.
*/
func analyzeImage(imageRef string, client anchoreImagesClient, authCtx context.Context) (anchore.AnchoreImage, error) {
	annotations := make(map[string]interface{})
	annotations["requestor"] = "anchore-admission-controller"

	opts := anchore.AddImageOpts{}
	opts.Autosubscribe = optional.NewBool(false)

	req := anchore.ImageAnalysisRequest{
		Tag:         imageRef,
		Annotations: annotations,
		CreatedAt:   time.Now().UTC().Round(time.Second),
	}

	imageList, _, err := client.AddImage(authCtx, req, &opts)

	if err != nil {
		return anchore.AnchoreImage{}, err
	}

	if len(imageList) == 0 {
		return anchore.AnchoreImage{}, errors.New("No image record received in successful response to image add request")
	}

	return imageList[0], nil
}

func isImageAnalyzed(imageRef string, client anchoreImagesClient, authCtx context.Context) (bool, anchore.AnchoreImage, error) {
	anchoreImage, err := lookupImage(imageRef, client, authCtx)
	if err != nil {
		return false, anchore.AnchoreImage{}, err
	}

	isAnalyzed := anchoreImage.AnalysisStatus == "analyzed"
	klog.Info("Image analyzed = ", isAnalyzed)

	return isAnalyzed, anchoreImage, nil
}

func lookupImage(imageRef string, client anchoreImagesClient, authCtx context.Context) (anchore.AnchoreImage, error) {
	localOptions := anchore.ListImagesOpts{}
	localOptions.Fulltag = optional.NewString(imageRef)
	klog.Info("Getting image from anchore engine. Reference=", imageRef)

	// Find latest image with tag
	images, _, err := client.ListImages(authCtx, &localOptions)
	if err != nil {
		return anchore.AnchoreImage{}, err
	}

	klog.Info("Getting image")
	if len(images) == 0 {
		return anchore.AnchoreImage{}, errors.New(fmt.Sprintf("No images found with tag %s", imageRef))
	}

	sort.Slice(images, func(i int, j int) bool {
		return images[i].CreatedAt.Before(images[j].CreatedAt)
	})

	return images[0], nil
}

func CheckImage(imageRef string, optionalPolicyId string, client anchoreImagesClient, authCtx context.Context) (bool, string, error) {
	anchoreImage, err := lookupImage(imageRef, client, authCtx)
	if err != nil {
		return false, "", err
	}

	digest := anchoreImage.ImageDigest

	localOptions := anchore.GetImagePolicyCheckOpts{}
	localOptions.Interactive = optional.NewBool(true)
	if optionalPolicyId != "" {
		localOptions.PolicyId = optional.NewString(optionalPolicyId)
	}

	evaluations, _, chkErr := client.GetImagePolicyCheck(authCtx, digest, imageRef, &localOptions)
	if chkErr != nil {
		return false, digest, chkErr
	}

	if len(evaluations) > 0 {
		resultStatus := findResult(evaluations[0])
		return strings.ToLower(resultStatus) == "pass", digest, nil
	}

	return false, digest, nil
}

func findResult(parsed_result map[string]interface{}) string {
	// Looks through a parsed result for the status value, assumes this result is for a single image
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

func initClient(username string, password string, endpoint string) (anchoreImagesClient, context.Context, error) {
	cfg := anchore.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.BasePath = endpoint

	// TODO: cert verification options?
	aClient := anchore.NewAPIClient(cfg)

	// TODO: timeouts
	// ctx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
	auth := context.WithValue(context.Background(), anchore.ContextBasicAuth, anchore.BasicAuth{UserName: username, Password: password})
	return aClient.ImagesApi, auth, nil
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

func main() {
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
