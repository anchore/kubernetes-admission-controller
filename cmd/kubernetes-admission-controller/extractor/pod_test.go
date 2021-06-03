package extractor

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
)

func TestFromPod(t *testing.T) {
	// arrange
	pod := v1.Pod{
		ObjectMeta: testPodObjectMeta,
		Spec:       testPodSpec,
	}
	request := mockAdmissionRequestFromPod(t, pod)

	// act
	actualMeta, actualPodSpecs, err := fromPod(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testPodObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromPod(t *testing.T, pod v1.Pod) v1beta1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "Pod", "pods", pod)
}

var (
	testPodObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_pod",
		Namespace: "namespace1",
	}
	testPodSpec = v1.PodSpec{
		Containers: []v1.Container{
			{
				Name:    "Container1",
				Image:   "ubuntu",
				Command: []string{"bin/bash", "bin"},
			},
		},
	}
)
