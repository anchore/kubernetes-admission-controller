package extractor

import (
	batchV1beta "k8s.io/api/batch/v1beta1"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	batchV1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromCronJob(t *testing.T) {
	// arrange
	cronJob := batchV1beta.CronJob{
		ObjectMeta: testCronJobObjectMeta,
		Spec:       testCronJobSpec,
	}
	request := mockAdmissionRequestFromCronJob(t, cronJob)

	// act
	actualMeta, actualPodSpecs, err := fromCronJob(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testCronJobObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromCronJob(t *testing.T, cronJob batchV1beta.CronJob) v1beta1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "CronJob", "cronjobs", cronJob)
}

var (
	testCronJobObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_cronjob",
		Namespace: "namespace1",
	}

	testCronJobSpec = batchV1beta.CronJobSpec{
		JobTemplate: batchV1beta.JobTemplateSpec{
			ObjectMeta: testCronJobObjectMeta,
			Spec: batchV1.JobSpec{
				Template: v1.PodTemplateSpec{
					Spec: testPodSpec,
				},
			},
		},
	}
)
