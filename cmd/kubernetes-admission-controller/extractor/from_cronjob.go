package extractor

import (
	"encoding/json"
	"k8s.io/api/admission/v1beta1"
	batchV1beta "k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforcing compliance with the Extractor type
var _ Extractor = fromCronJob

// fromCronJob returns the extracted object metadata and included v1.PodSpecs from the CronJob admission request.
func fromCronJob(admissionRequest v1beta1.AdmissionRequest) (metav1.ObjectMeta, []v1.PodSpec, error) {
	var cronJob batchV1beta.CronJob
	err := json.Unmarshal(admissionRequest.Object.Raw, &cronJob)
	if err != nil {
		return metav1.ObjectMeta{}, nil, err
	}

	return cronJob.ObjectMeta, []v1.PodSpec{cronJob.Spec.JobTemplate.Spec.Template.Spec}, nil
}
