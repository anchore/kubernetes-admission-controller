package extractor

import (
	"encoding/json"

	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromStatefulSet

// fromDeployment returns the extracted object metadata and included v1.PodSpecs from the Deployment admission request.
func fromStatefulSet(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var statefulSet appsV1.StatefulSet
	err := json.Unmarshal(admissionRequest.Object.Raw, &statefulSet)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return statefulSet.ObjectMeta, []v1.PodSpec{statefulSet.Spec.Template.Spec}, nil
}

