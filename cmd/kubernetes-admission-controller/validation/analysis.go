package validation

import (
	"errors"
	"fmt"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"k8s.io/klog"
)

// analysis performs the "analysis mode" validation and returns a Result.
func analysis(imageBackend anchore.ImageBackend, asUser anchore.Credential, imageReference string) Result {
	if imageBackend == nil {
		message := "failing analysis validation: missing Anchore image client (likely due to missing credentials)"
		klog.Error(message)
		return Result{IsValid: false, Message: message}
	}

	klog.Info("performing validation that the image is analyzed by Anchore")

	image, err := imageBackend.Get(asUser, imageReference)
	if err != nil {
		if errors.Is(err, anchore.ErrImageDoesNotExist) {
			message := fmt.Sprintf("image %q is not analyzed", imageReference)
			klog.Info(message)
			return Result{IsValid: false, Message: message}
		}

		message := fmt.Sprintf("error checking Anchore for image analysis status: %v", err)
		klog.Error(message)
		return Result{IsValid: false, Message: message}
	}

	if image.AnalysisStatus == anchore.ImageStatusAnalyzed {
		message := fmt.Sprintf("image %q with digest %q is analyzed", imageReference, image.Digest)
		klog.Info(message)
		return Result{IsValid: true, Message: message, ImageDigest: image.Digest}
	}

	message := fmt.Sprintf("image %q with digest %q is not analyzed", imageReference, image.Digest)
	klog.Info(message)
	return Result{IsValid: false, Message: message, ImageDigest: image.Digest}
}
