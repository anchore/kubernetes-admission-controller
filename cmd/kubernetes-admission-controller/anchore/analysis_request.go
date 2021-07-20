package anchore

import (
	"k8s.io/klog"
)

// analysisRequest describes an intended request to a given ImageBackend for the provided imageReference to be added
// for analysis. This request is not actually sent until dispatch is called.
type analysisRequest struct {
	imageBackend   ImageBackend
	user           Credential
	imageReference string
}

// dispatch sends the request for image analysis to the ImageBackend associated with this analysisRequest.
func (r analysisRequest) dispatch() {
	if r.imageBackend == nil {
		klog.Infof("unable to dispatch request for %q: Anchore image client unavailable", r.imageReference)
		return
	}

	klog.Infof("dispatching analysis request to Anchore for image %q", r.imageReference)

	err := r.imageBackend.Analyze(r.user, r.imageReference)
	if err != nil {
		klog.Infof("analysis request encountered an error (this doesn't impact the validation result): %v", err)
	}
}
