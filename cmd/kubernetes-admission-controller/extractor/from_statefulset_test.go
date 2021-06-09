package extractor

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromStatefulSet(t *testing.T) {
	// arrange
	statefulSet := appsV1.StatefulSet{
		ObjectMeta: testStatefulSetObjectMeta,
		Spec:       testStatefulSetSpec,
	}
	request := mockAdmissionRequestFromStatefulSet(t, statefulSet)

	// act
	actualMeta, actualPodSpecs, err := fromStatefulSet(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testStatefulSetObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromStatefulSet(t *testing.T, statefulSet appsV1.StatefulSet) v1beta1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "StatefulSet", "statefulsets", statefulSet)
}

var (
	testStatefulSetObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_statefulset",
		Namespace: "namespace1",
	}
	testStatefulSetSpec = appsV1.StatefulSetSpec{
		Template: v1.PodTemplateSpec{
			Spec: testPodSpec,
		},
	}
)
