package validation

import (
	"fmt"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"k8s.io/klog"
)

// policy performs the "policy mode" validation and returns a Result.
func policy(imageBackend anchore.ImageBackend, asUser anchore.Credential, imageReference,
	policyBundleID string) Result {
	analysisValidationResult := analysis(imageBackend, asUser, imageReference)
	if analysisValidationResult.IsValid == false {
		return analysisValidationResult
	}

	klog.Info("performing validation that the image passes policy evaluation in Anchore")

	imageDigest := analysisValidationResult.ImageDigest
	doesCheckPass, err := imageBackend.DoesPolicyCheckPass(asUser, imageDigest, imageReference, policyBundleID)
	if err != nil {
		message := fmt.Sprintf("error checking if policy check passes for image %q: %s", imageDigest, err)
		klog.Error(message)
		return Result{IsValid: false, Message: message, ImageDigest: imageDigest}
	}

	if doesCheckPass {
		message := fmt.Sprintf("image %q with digest %q PASSED policy checks for policy bundle %q", imageReference,
			imageDigest, policyBundleID)
		klog.Info(message)
		return Result{IsValid: true, Message: message, ImageDigest: imageDigest}
	}

	message := fmt.Sprintf("image %q with digest %q FAILED policy checks for policy bundle %q", imageReference,
		imageDigest, policyBundleID)
	klog.Info(message)
	return Result{IsValid: false, Message: message, ImageDigest: imageDigest}
}
