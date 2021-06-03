package extractor

import (
	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Extractor is a function type for implementations that can respond to Kubernetes admission controller requests for
// an object and return that object's metadata and any PodSpecs contained within the object.
type Extractor func(v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error)

// ForAdmissionRequest returns an Extractor function for the Kubernetes object contained in the given
// AdmissionRequest. If no Extractor is available for the given admission request, ForAdmissionRequest returns nil.
func ForAdmissionRequest(request v1beta1.AdmissionRequest) Extractor {
	extractor, found := extractors[request.Kind]
	if !found {
		return nil
	}

	return extractor
}

var extractors = map[metav1.GroupVersionKind]Extractor{
	metav1.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "Pod",
	}: fromPod,
	metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	}: fromDeployment,
}
