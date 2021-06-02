package kubernetes

import (
	"encoding/json"

	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = deploymentExtractor

// deploymentExtractor returns the object metadata and included v1.PodSpecs for the requested Deployment object.
func deploymentExtractor(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var deployment appsV1.Deployment
	err := json.Unmarshal(admissionRequest.Object.Raw, &deployment)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return deployment.ObjectMeta, []v1.PodSpec{deployment.Spec.Template.Spec}, nil
}
