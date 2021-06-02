package anchore

import (
	"testing"
)

func TestAnalysisRequest_Dispatch(t *testing.T) {
	// arrange
	const imageReference = "some-image:latest"
	imageProvider := new(mockImageProvider)
	imageProvider.On("Analyze", imageReference).Return(nil)

	request := analysisRequest{
		imageProvider:  imageProvider,
		imageReference: imageReference,
	}

	// act
	request.dispatch()

	// assert
	imageProvider.AssertCalled(t, "Analyze", imageReference)
}
