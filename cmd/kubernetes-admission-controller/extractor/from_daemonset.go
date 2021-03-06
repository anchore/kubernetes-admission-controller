package extractor

import (
	"encoding/json"

	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromDaemonSet

// fromDaemonSet returns the extracted object metadata and included v1.PodSpecs from the DaemonSet admission request.
func fromDaemonSet(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var daemonSet appsV1.DaemonSet
	err := json.Unmarshal(admissionRequest.Object.Raw, &daemonSet)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return daemonSet.ObjectMeta, []v1.PodSpec{daemonSet.Spec.Template.Spec}, nil
}

