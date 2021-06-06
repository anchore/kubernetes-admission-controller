package extractor

import (
	"encoding/json"

	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromPod

// fromPod returns the extracted object metadata and v1.PodSpec from the Pod admission request.
func fromPod(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var pod v1.Pod
	err := json.Unmarshal(admissionRequest.Object.Raw, &pod)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}
	return pod.ObjectMeta, []v1.PodSpec{pod.Spec}, nil
}
