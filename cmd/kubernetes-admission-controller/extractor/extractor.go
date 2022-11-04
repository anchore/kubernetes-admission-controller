package extractor

import (
	admissionV1 "k8s.io/api/admission/v1"
	appsV1 "k8s.io/api/apps/v1"
	batchV1 "k8s.io/api/batch/v1"
	batchV1beta "k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Extractor is a function type for implementations that can respond to Kubernetes admission controller requests for
// an object and return that object's metadata and any PodSpecs contained within the object.
type Extractor func(admissionV1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error)

// ForAdmissionRequest returns an Extractor function for the Kubernetes object contained in the given
// AdmissionRequest. If no Extractor is available for the given admission request, ForAdmissionRequest returns nil.
func ForAdmissionRequest(request admissionV1.AdmissionRequest) Extractor {
	extractor, found := extractors[request.Kind]
	if !found {
		return nil
	}

	return extractor
}

// extractors is a mapping of supported kinds of resources to available Extractors.
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
	metav1.GroupVersionKind{
		Group:   batchV1.SchemeGroupVersion.Group,
		Version: batchV1.SchemeGroupVersion.Version,
		Kind:    "Job",
	}: fromJob,
	metav1.GroupVersionKind{
		Group:   batchV1beta.SchemeGroupVersion.Group,
		Version: batchV1beta.SchemeGroupVersion.Version,
		Kind:    "CronJob",
	}: fromCronJob,
	metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "DaemonSet",
	}: fromDaemonSet,
	metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "StatefulSet",
	}: fromStatefulSet,
	metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "ReplicaSet",
	}: fromReplicaSet,
}
