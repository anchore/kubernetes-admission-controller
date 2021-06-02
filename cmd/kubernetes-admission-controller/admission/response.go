package admission

import (
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func responseFromValidationResult(request v1beta1.AdmissionRequest, result validation.Result) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
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
