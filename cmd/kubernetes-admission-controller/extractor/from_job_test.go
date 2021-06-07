package extractor

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	batchV1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromJob(t *testing.T) {
	// arrange
	job := batchV1.Job{
		ObjectMeta: testDeploymentObjectMeta,
		Spec:       testJobSpec,
	}
	request := mockAdmissionRequestFromJob(t, job)

	// act
	actualMeta, actualPodSpecs, err := fromJob(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testDeploymentObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromJob(t *testing.T, job batchV1.Job) v1beta1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "Deployment", "deployments", job)
}

var (
	testJobObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_deployment",
		Namespace: "namespace1",
	}
	testJobSpec = batchV1.JobSpec{
		Template: v1.PodTemplateSpec{
			Spec: testPodSpec,
		},
	}
)
