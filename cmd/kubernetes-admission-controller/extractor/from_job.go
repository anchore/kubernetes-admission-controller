package extractor

import (
	"encoding/json"
	admissionV1 "k8s.io/api/admission/v1"

	batchV1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromJob

// fromJob returns the extracted object metadata and included v1.PodSpecs from the Job admission request.
func fromJob(admissionRequest admissionV1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var job batchV1.Job
	err := json.Unmarshal(admissionRequest.Object.Raw, &job)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return job.ObjectMeta, []v1.PodSpec{job.Spec.Template.Spec}, nil
}
