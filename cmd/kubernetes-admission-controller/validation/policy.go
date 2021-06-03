package validation

import (
	"fmt"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"k8s.io/klog"
)

// Policy performs the "policy mode" validation and returns a Result.
func Policy(imageBackend anchore.ImageBackend, imageReference, policyBundleID string) Result {
	analysisValidationResult := Analysis(imageBackend, imageReference)
	if analysisValidationResult.IsValid == false {
		return analysisValidationResult
	}

	klog.Info("Performing validation that the image passes policy evaluation in Anchore")

	imageDigest := analysisValidationResult.ImageDigest
	doesCheckPass, err := imageBackend.DoesPolicyCheckPass(imageDigest, imageReference, policyBundleID)
	if err != nil {
		message := fmt.Sprintf("error checking if policy check passes for image %q: %s", imageDigest, err)
		klog.Error(message)
		return Result{IsValid: false, Message: message, ImageDigest: imageDigest}
	}

	if doesCheckPass {
		message := fmt.Sprintf("Image %q with digest %q passed policy checks for policy bundle %q", imageReference,
			imageDigest, policyBundleID)
		klog.Info(message)
		return Result{IsValid: true, Message: message, ImageDigest: imageDigest}
	}

	message := fmt.Sprintf("Image %q with digest %q failed policy checks for policy bundle %q", imageReference, imageDigest, policyBundleID)
	klog.Info(message)
	return Result{IsValid: false, Message: message, ImageDigest: imageDigest}
}
