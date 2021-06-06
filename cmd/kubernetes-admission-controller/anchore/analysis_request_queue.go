package anchore

// AnalysisRequestQueue provides a mechanism by which analysis requests can be queued incrementally (
// via Add) and then dispatched together later (via DispatchAll).
type AnalysisRequestQueue struct {
	requests []analysisRequest
}

// NewAnalysisRequestQueue returns a new, initialized AnalysisRequestQueue.
func NewAnalysisRequestQueue() AnalysisRequestQueue {
	return AnalysisRequestQueue{}
}

func (q *AnalysisRequestQueue) Add(imageBackend ImageBackend, imageReference string) {
	q.requests = append(q.requests, analysisRequest{imageBackend, imageReference})
}

func (q *AnalysisRequestQueue) ImportRequestsFrom(other AnalysisRequestQueue) {
	q.requests = append(q.requests, other.requests...)
}

func (q *AnalysisRequestQueue) DispatchAll() {
	for _, request := range q.requests {
		request.dispatch()
	}

	q.requests = nil
}
