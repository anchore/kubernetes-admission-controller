package extractor

import (
	admissionV1 "k8s.io/api/admission/v1"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromDeployment(t *testing.T) {
	// arrange
	deployment := appsV1.Deployment{
		ObjectMeta: testDeploymentObjectMeta,
		Spec:       testDeploymentSpec,
	}
	request := mockAdmissionRequestFromDeployment(t, deployment)

	// act
	actualMeta, actualPodSpecs, err := fromDeployment(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testDeploymentObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromDeployment(t *testing.T, deployment appsV1.Deployment) admissionV1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "Deployment", "deployments", deployment)
}

var (
	testDeploymentObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_deployment",
		Namespace: "namespace1",
	}
	testDeploymentSpec = appsV1.DeploymentSpec{
		Template: v1.PodTemplateSpec{
			Spec: testPodSpec,
		},
	}
)
