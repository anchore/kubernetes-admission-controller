package anchore

import (
	"testing"
)

func TestAnalysisRequest_Dispatch(t *testing.T) {
	// arrange
	const imageReference = "some-image:latest"
	imageBackend := new(MockImageBackend)
	imageBackend.On("Analyze", imageReference).Return(nil)

	request := analysisRequest{
		imageBackend:   imageBackend,
		imageReference: imageReference,
	}

	// act
	request.dispatch()

	// assert
	imageBackend.AssertCalled(t, "Analyze", imageReference)
}
