package anchore

import (
	"testing"
)

func TestAnalysisRequestQueue_DispatchAll(t *testing.T) {
	const imageReference = "some-image:latest"
	imageBackend := new(MockImageBackend)
	mockUser := Credential{}
	imageBackend.On("Analyze", mockUser, imageReference).Return(nil)

	queue := NewAnalysisRequestQueue()

	expectedAnalyzeCalls := 0

	// No requests queued yet
	queue.DispatchAll()
	imageBackend.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Adding requests to queue via `Add`
	queue.Add(imageBackend, mockUser, imageReference)
	queue.Add(imageBackend, mockUser, imageReference)
	expectedAnalyzeCalls += 2

	// Two requests queued
	queue.DispatchAll()
	imageBackend.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Queue should have been cleared in previous `DispatchAll` call
	queue.DispatchAll()
	imageBackend.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)

	// Adding requests to queue via `ImportRequestsFrom`
	otherQueue := AnalysisRequestQueue{
		requests: []analysisRequest{
			{
				imageBackend:   imageBackend,
				imageReference: imageReference,
			},
		},
	}

	queue.ImportRequestsFrom(otherQueue)
	expectedAnalyzeCalls += 1

	queue.DispatchAll()
	imageBackend.AssertNumberOfCalls(t, "Analyze", expectedAnalyzeCalls)
}
