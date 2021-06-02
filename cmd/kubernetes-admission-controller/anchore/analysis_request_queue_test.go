package anchore

import "testing"

func TestAnalysisRequestQueue_DispatchAll(t *testing.T) {
	const imageReference = "some-image:latest"
	imageProvider := new(mockImageProvider)
	imageProvider.On("Analyze", imageReference).Return(nil)

	queue := NewAnalysisRequestQueue()

	expectedAnalyzeCalls := 0

	// No requests queued yet
	queue.DispatchAll()
	imageProvider.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Adding requests to queue via `Add`
	queue.Add(imageProvider, imageReference)
	queue.Add(imageProvider, imageReference)
	expectedAnalyzeCalls += 2

	// Two requests queued
	queue.DispatchAll()
	imageProvider.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Queue should have been cleared in previous `DispatchAll` call
	queue.DispatchAll()
	imageProvider.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Adding requests to queue via `ImportRequestsFrom`
	otherQueue := AnalysisRequestQueue{
		requests: []analysisRequest{
			{
				imageProvider:  imageProvider,
				imageReference: imageReference,
			},
		},
	}

	queue.ImportRequestsFrom(otherQueue)
	expectedAnalyzeCalls += 1

	queue.DispatchAll()
	imageProvider.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)
}
