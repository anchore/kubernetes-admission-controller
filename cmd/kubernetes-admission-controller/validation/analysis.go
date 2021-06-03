package validation

import (
	"errors"
	"fmt"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"k8s.io/klog"
)

// Analysis performs the "analysis mode" validation and returns a Result.
func Analysis(imageBackend anchore.ImageBackend, imageReference string) Result {
	if imageBackend == nil {
		message := "No valid policy reference with valid credentials found. Failing validation"
		klog.Error(message)
		return Result{IsValid: false, Message: message}
	}

	klog.Info("Performing validation that the image is analyzed by Anchore")

	image, err := imageBackend.Get(imageReference)
	if err != nil {
		if errors.Is(err, anchore.ErrImageDoesNotExist) {
			message := fmt.Sprintf("Image %q is not analyzed", imageReference)
			klog.Info(message)
			return Result{IsValid: false, Message: message}
		}

		message := fmt.Sprintf("error checking Anchore for image analysis status: %v", err)
		klog.Error(message)
		return Result{IsValid: false, Message: message}
	}

	if image.AnalysisStatus == anchore.ImageStatusAnalyzed {
		message := fmt.Sprintf("Image %q with digest %q is analyzed", imageReference, image.Digest)
		klog.Info(message)
		return Result{IsValid: true, Message: message, ImageDigest: image.Digest}
	}

	message := fmt.Sprintf("Image %q with digest %q is not analyzed", imageReference, image.Digest)
	klog.Info(message)
	return Result{IsValid: false, Message: message, ImageDigest: image.Digest}
}
