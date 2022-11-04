package extractor

import (
	"encoding/json"
	admissionV1 "k8s.io/api/admission/v1"
	"testing"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func mockAdmissionRequestFromObject(t *testing.T, kind, resource string, object interface{}) admissionV1.AdmissionRequest {
	t.Helper()

	marshalledObject, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("Failed to marshal %q: %v", kind, err)
	}

	return admissionV1.AdmissionRequest{
		UID:         "abc123",
		Kind:        metav1.GroupVersionKind{Group: v1beta1.GroupName, Version: v1beta1.SchemeGroupVersion.Version, Kind: kind},
		Resource:    metav1.GroupVersionResource{Group: metav1.GroupName, Version: "v1", Resource: resource},
		SubResource: "someresource",
		Name:        "somename",
		Namespace:   "default",
		Operation:   "CREATE",
		Object:      runtime.RawExtension{Raw: marshalledObject},
	}
}
