package validation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
)

const testImageReference = "some-image:latest"

func TestAnalysis(t *testing.T) {
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
			name: "image does not exist",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				backend.On("Get", mock.Anything, testImageReference).Return(anchore.Image{},
					anchore.ErrImageDoesNotExist)
				return backend
			})(),
			isExpectedToBeValid: false,
		},
		{
			name: "error on image lookup",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				backend.On("Get", mock.Anything, testImageReference).Return(anchore.Image{},
					errors.New("some other error"))

				return backend
			})(),
			isExpectedToBeValid: false,
		},
		{
			name: "image is analyzed",
			imageBackend: (func() anchore.ImageBackend {
				backend := new(anchore.MockImageBackend)
				image := anchore.Image{
					AnalysisStatus: anchore.ImageStatusAnalyzed,
				}
				backend.On("Get", mock.Anything, testImageReference).Return(image, nil)

				return backend
			})(),
			isExpectedToBeValid: true,
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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockUser := anchore.Credential{}

			actual := analysis(testCase.imageBackend, mockUser, testImageReference)

			assert.Equal(t, testCase.isExpectedToBeValid, actual.IsValid)
		})
	}
}
