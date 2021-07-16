package anchore

import (
	"testing"
)

func TestAnalysisRequest_Dispatch(t *testing.T) {
	// arrange
	const imageReference = "some-image:latest"
	imageBackend := new(MockImageBackend)
	mockUser := Credential{}
	imageBackend.On("Analyze", mockUser, imageReference).Return(nil)

	request := analysisRequest{
		imageBackend:   imageBackend,
		user:           mockUser,
		imageReference: imageReference,
	}

	// act
	request.dispatch()

	// assert
	imageBackend.AssertCalled(t, "Analyze", mockUser, imageReference)
}
