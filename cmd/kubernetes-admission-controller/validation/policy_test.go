package validation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

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
				backend.On("Get", mock.Anything, testImageReference).Return(image, nil)

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
				backend.On("Get", mock.Anything, testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", mock.Anything, testImageDigest, testImageReference, testPolicyBundleID).Return(false,
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
				backend.On("Get", mock.Anything, testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", mock.Anything, testImageDigest, testImageReference, testPolicyBundleID).Return(true, nil)

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
				backend.On("Get", mock.Anything, testImageReference).Return(image, nil)
				backend.On("DoesPolicyCheckPass", mock.Anything, testImageDigest, testImageReference,
					testPolicyBundleID).Return(false, nil)

				return backend
			})(),
			isExpectedToBeValid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockUser := anchore.Credential{}

			actual := policy(testCase.imageBackend, mockUser, testImageReference, testPolicyBundleID)

			assert.Equal(t, testCase.isExpectedToBeValid, actual.IsValid)
		})
	}
}

func TestPolicy_EmptyPolicyBundleID(t *testing.T) {
	// An empty PolicyBundleId means "evaluate against the account's default
	// bundle": policy() must pass the empty ID through to the backend unchanged,
	// so the API backend can omit the policy-ID parameter from the evaluation
	// request (see APIImageBackend.DoesPolicyCheckPass). It must not error or
	// deny just because no explicit bundle is configured.
	testCases := []struct {
		name                string
		doesPolicyCheckPass bool
	}{
		{
			name:                "passes policy check against default bundle",
			doesPolicyCheckPass: true,
		},
		{
			name:                "fails policy check against default bundle",
			doesPolicyCheckPass: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := new(anchore.MockImageBackend)
			image := anchore.Image{
				Digest:         testImageDigest,
				AnalysisStatus: anchore.ImageStatusAnalyzed,
			}
			backend.On("Get", mock.Anything, testImageReference).Return(image, nil)
			backend.On("DoesPolicyCheckPass", mock.Anything, testImageDigest, testImageReference,
				"").Return(testCase.doesPolicyCheckPass, nil)

			actual := policy(backend, anchore.Credential{}, testImageReference, "")

			assert.Equal(t, testCase.doesPolicyCheckPass, actual.IsValid)
			backend.AssertCalled(t, "DoesPolicyCheckPass", mock.Anything, testImageDigest, testImageReference, "")
		})
	}
}
