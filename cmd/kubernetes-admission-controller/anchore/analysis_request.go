package anchore

import (
	"k8s.io/klog"
)

// analysisRequest describes an intended request to a given ImageBackend for the provided imageReference to be added
// for analysis. This request is not actually sent until dispatch is called.
type analysisRequest struct {
	imageBackend   ImageBackend
	imageReference string
}

// dispatch sends the request for image analysis to the ImageBackend associated with this analysisRequest.
func (r analysisRequest) dispatch() {
	if r.imageBackend == nil {
		klog.Info("Image analysis request configured but no credentials mapped to execute the call. Skipping")
		return
	}

	klog.Info("Requesting analysis of image ", "image=", r.imageReference)

	err := r.imageBackend.Analyze(r.imageReference)
	if err != nil {
		klog.Info("Error requesting analysis of image, but ignoring for validation result. err=", err)
	}
}
