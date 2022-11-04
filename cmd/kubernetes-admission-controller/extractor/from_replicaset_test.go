package extractor

import (
	admissionV1 "k8s.io/api/admission/v1"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	appsV1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

func TestFromReplicaSet(t *testing.T) {
	// arrange
	replicaSet := appsV1.ReplicaSet{
		ObjectMeta: testReplicaSetObjectMeta,
		Spec:       testReplicaSetSpec,
	}
	request := mockAdmissionRequestFromReplicaSet(t, replicaSet)

	// act
	actualMeta, actualPodSpecs, err := fromReplicaSet(request)

	// assert
	assert.NoError(t, err)
	assert.EqualValues(t, testReplicaSetObjectMeta, actualMeta)
	assert.Contains(t, actualPodSpecs, testPodSpec)
}

func mockAdmissionRequestFromReplicaSet(t *testing.T, replicaSet appsV1.ReplicaSet) admissionV1.AdmissionRequest {
	t.Helper()

	return mockAdmissionRequestFromObject(t, "ReplicaSet", "replicasets", replicaSet)
}

var (
	testReplicaSetObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_replicaset",
		Namespace: "namespace1",
	}
	testReplicaSetSpec = appsV1.ReplicaSetSpec{
		Template: v1.PodTemplateSpec{
			Spec: testPodSpec,
		},
	}
)
