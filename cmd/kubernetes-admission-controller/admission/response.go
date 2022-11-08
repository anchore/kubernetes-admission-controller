package admission

import (
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
	admissionV1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func response(request admissionV1.AdmissionRequest, result validation.Result) *admissionV1.AdmissionResponse {
	return &admissionV1.AdmissionResponse{
		Allowed: result.IsValid,
		UID:     request.UID,
		Result: &metav1.Status{
			Status:  statusFromBool(result.IsValid),
			Message: result.Message,
		},
	}
}

func statusFromBool(b bool) string {
	if b {
		return metav1.StatusSuccess
	}

	return metav1.StatusFailure
}
