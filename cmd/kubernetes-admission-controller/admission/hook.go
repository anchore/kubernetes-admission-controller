package admission

import (
	"fmt"
	admissionV1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "k8s.io/api/core/v1"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"

	k8s "k8s.io/client-go/kubernetes"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/extractor"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

// Hook is the Anchore-specific implementation of a Kubernetes validating admission hook.
type Hook struct {
	config       *ControllerConfiguration
	clientset    *k8s.Clientset
	anchoreAuth  *anchore.AuthConfiguration
	imageBackend anchore.ImageBackend
}

// NewHook creates and returns a new Hook.
func NewHook(
	config *ControllerConfiguration,
	clientset *k8s.Clientset,
	anchoreAuth *anchore.AuthConfiguration,
	imageBackend anchore.ImageBackend,
) *Hook {
	return &Hook{config: config, clientset: clientset, anchoreAuth: anchoreAuth, imageBackend: imageBackend}
}

func (h *Hook) Initialize(*rest.Config, <-chan struct{}) error {
	klog.Info("Initializing handler")
	return nil
}

func (h *Hook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	return schema.GroupVersionResource{
		Group:    "admission.anchore.io",
		Version:  "v1beta1",
		Resource: "imagechecks",
	}, "imagecheck"
}

func (h *Hook) Validate(admissionRequest *admissionV1.AdmissionRequest) *admissionV1.AdmissionResponse {
	if admissionRequest == nil {
		return nil
	}
	request := *admissionRequest

	klog.Infof("validating new admission request — name: %q, kind: %q", admissionRequest.Name, admissionRequest.Kind)

	result, analysisRequestQueue := h.evaluateKubernetesObject(request)
	analysisRequestQueue.DispatchAll()

	return response(request, result)
}

// evaluateKubernetesObject looks for container image references in the requested object and performs validation
// based on user-supplied configuration.
func (h Hook) evaluateKubernetesObject(request admissionV1.AdmissionRequest) (validation.Result, anchore.AnalysisRequestQueue) {
	queue := anchore.NewAnalysisRequestQueue()

	extractFunc := extractor.ForAdmissionRequest(request)
	if extractFunc == nil {
		message := fmt.Sprintf(
			"unsupported admission request kind (request UID: %s): %q",
			request.UID,
			request.Kind,
		)
		klog.Info(message)
		result := validation.Result{IsValid: true, Message: message}

		return result, queue
	}

	meta, podSpecs, err := extractFunc(request)
	if err != nil {
		message := fmt.Sprintf("error parsing admission request to extract object kind and metadata: %v", err)
		klog.Error(message)
		result := validation.Result{IsValid: false, Message: message}

		return result, queue
	}

	if len(podSpecs) == 0 {
		message := "no pod specs found to validate"
		klog.Info(message)
		result := validation.Result{IsValid: true, Message: message}

		return result, queue
	}

	var podResults []validation.Result

	for _, podSpec := range podSpecs {
		podResult, podQueue := h.evaluatePod(meta, podSpec)
		podResults = append(podResults, podResult)
		queue.ImportRequestsFrom(podQueue)
	}

	objectResult := validation.Reduce(podResults, "results for pods:")

	return objectResult, queue
}

// evaluatePod looks for container image references in the pod and performs validation
// based on user-supplied configuration.
func (h Hook) evaluatePod(meta metav1.ObjectMeta, podSpec v1.PodSpec) (validation.Result,
	anchore.AnalysisRequestQueue) {
	queue := anchore.NewAnalysisRequestQueue()

	containers := podSpec.Containers

	if len(containers) == 0 {
		message := fmt.Sprintf("no container specs to validate for pod %q", meta.String())
		klog.Info(message)
		result := validation.Result{IsValid: true, Message: message}

		return result, queue
	}

	var imageResults []validation.Result

	for _, container := range containers {
		imageResult, queueFromImage := h.evaluateImage(meta, container.Image)
		imageResults = append(imageResults, imageResult)
		queue.ImportRequestsFrom(queueFromImage)
	}

	podResult := validation.Reduce(imageResults, "results for images:")

	return podResult, queue
}

// evaluateImage performs validation on the given container image based on user-supplied configuration.
func (h Hook) evaluateImage(meta metav1.ObjectMeta, imageReference string) (validation.Result, anchore.AnalysisRequestQueue) {
	klog.Info("evaluating selectors for image=", imageReference)

	requestQueue := anchore.NewAnalysisRequestQueue()

	c := validation.NewConfiguration(meta, imageReference, h.config.PolicySelectors, *h.clientset)
	if c == nil {
		// No rule matched, so skip this image
		message := fmt.Sprintf("no selector match found for image %q", imageReference)
		klog.Info(message)
		return validation.Result{IsValid: true, Message: message, ImageDigest: ""}, requestQueue
	}
	configuration := *c

	klog.Infof("validation configuration determined: %+v", configuration)

	user, err := anchore.SelectUserCredential(h.anchoreAuth.Users, configuration.PolicyReference.Username)
	if err != nil {
		message := fmt.Sprintf("validation not possible: %v", err)
		klog.Error(message)
		return validation.Result{
			IsValid: false,
			Message: message,
		}, requestQueue
	}

	validator, err := validation.New(configuration, h.imageBackend, user, imageReference)
	if err != nil {
		message := fmt.Sprintf("unable to validate: %v", err)
		klog.Error(message)
		return validation.Result{
			IsValid: false,
			Message: message,
		}, requestQueue
	}

	result := validator()

	if shouldRequestAnalysis(result, *h.config) {
		requestQueue.Add(h.imageBackend, user, imageReference)
	}

	klog.Infof("image evaluation result: %+v", result)

	return result, requestQueue
}

func shouldRequestAnalysis(result validation.Result, config ControllerConfiguration) bool {
	if !config.Validator.RequestAnalysis {
		return false
	}

	return result.Mode == validation.BreakGlassMode || (!result.IsValid && result.ImageDigest == "")
}
