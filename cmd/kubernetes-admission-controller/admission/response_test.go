package admission

import (
	admissionV1 "k8s.io/api/admission/v1"
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
)

func TestResponse(t *testing.T) {
	testCases := []struct {
		name     string
		request  admissionV1.AdmissionRequest
		result   validation.Result
		expected *admissionV1.AdmissionResponse
	}{
		{
			name:    "success",
			request: testAdmissionRequest,
			result: validation.Result{
				IsValid: true,
				Message: testValidationResultMessage,
			},
			expected: &admissionV1.AdmissionResponse{
				Allowed: true,
				UID:     testUID,
				Result: &metav1.Status{
					Status:  "Success",
					Message: testValidationResultMessage,
				},
			},
		},
		{
			name:    "failure",
			request: testAdmissionRequest,
			result: validation.Result{
				IsValid: false,
				Message: testValidationResultMessage,
			},
			expected: &admissionV1.AdmissionResponse{
				Allowed: false,
				UID:     testUID,
				Result: &metav1.Status{
					Status:  "Failure",
					Message: testValidationResultMessage,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := response(testCase.request, testCase.result)

			assert.EqualValues(t, testCase.expected, actual)
		})
	}
}

var (
	testAdmissionRequest = admissionV1.AdmissionRequest{
		UID: testUID,
	}
	testUID                     = types.UID("some-uid")
	testValidationResultMessage = "some-message"
)
