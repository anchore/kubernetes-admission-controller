package extractor

import (
	admissionV1 "k8s.io/api/admission/v1"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromDaemonSet(t *testing.T) {
	// arrange
	daemonSet := appsV1.DaemonSet{
		ObjectMeta: testDaemonSetObjectMeta,
		Spec:       testDaemonSetSpec,
	}
	request := mockAdmissionRequestFromDaemonSet(t, daemonSet)

	// act
	actualMeta, actualPodSpecs, err := fromDaemonSet(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testDaemonSetObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromDaemonSet(t *testing.T, daemonSet appsV1.DaemonSet) admissionV1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "DaemonSet", "daemonsets", daemonSet)
}

var (
	testDaemonSetObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_daemonset",
		Namespace: "namespace1",
	}
	testDaemonSetSpec = appsV1.DaemonSetSpec{
		Template: v1.PodTemplateSpec{
			Spec: testPodSpec,
		},
	}
)
