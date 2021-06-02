package anchore

import "k8s.io/klog"

type analysisRequest struct {
	imageProvider  ImageProvider
	imageReference string
}

func (r analysisRequest) dispatch() {
	if r.imageProvider == nil {
		klog.Info("Image analysis request configured but no credentials mapped to execute the call. Skipping")
		return
	}

	klog.Info("Requesting analysis of image ", "image=", r.imageReference)

	err := r.imageProvider.Analyze(r.imageReference)
	if err != nil {
		klog.Info("Error requesting analysis of image, but ignoring for validation result. err=", err)
	}
}
