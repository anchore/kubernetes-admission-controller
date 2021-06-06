package validation

import (
	"errors"
	"testing"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
	"github.com/stretchr/testify/assert"
)

const (
	testImageDigest    = "some-digest"
	testPolicyBundleID = "policy-123"
)

func TestPolicy(t *testing.T) {
	testCases := []struct {
		name                string
		imageBackend        anchore.ImageBackend
		isExpectedToBeValid bool
	}{
		{
			name:                "no image backend provided",
			imageBackend:        nil,
			isExpectedToBeValid: false,
		},
		{
			name: "image is not analyzed",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				image := anchore.Image{
					AnalysisStatus: "not-analyzed",
				}
				backend.On("Get", testImageReference).Return(image, nil)

				return backend
			})(),
			isExpectedToBeValid: false,
		},
		{
			name: "error on policy check",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				image := anchore.Image{
					Digest:         testImageDigest,
					AnalysisStatus: anchore.ImageStatusAnalyzed,
				}
				backend.On("Get", testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", testImageDigest, testImageReference, testPolicyBundleID).Return(false,
					errors.New("some error"))

				return backend
			})(),
			isExpectedToBeValid: false,
		},
		{
			name: "passes policy check",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				image := anchore.Image{
					Digest:         testImageDigest,
					AnalysisStatus: anchore.ImageStatusAnalyzed,
				}
				backend.On("Get", testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", testImageDigest, testImageReference, testPolicyBundleID).Return(true,
					nil)

				return backend
			})(),
			isExpectedToBeValid: true,
		},
		{
			name: "fails policy check",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				image := anchore.Image{
					Digest:         testImageDigest,
					AnalysisStatus: anchore.ImageStatusAnalyzed,
				}
				backend.On("Get", testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", testImageDigest, testImageReference, testPolicyBundleID).Return(false,
					nil)

				return backend
			})(),
			isExpectedToBeValid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := Policy(testCase.imageBackend, testImageReference, testPolicyBundleID)

			assert.Equal(t, testCase.isExpectedToBeValid, actual.IsValid)
		})
	}
}
