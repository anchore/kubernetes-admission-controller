package extractor

import (
	"encoding/json"

	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromReplicaSet

// fromDeployment returns the extracted object metadata and included v1.PodSpecs from the Deployment admission request.
func fromReplicaSet(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var replicaSet appsV1.ReplicaSet
	err := json.Unmarshal(admissionRequest.Object.Raw, &replicaSet)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return replicaSet.ObjectMeta, []v1.PodSpec{replicaSet.Spec.Template.Spec}, nil
}

