package anchore

import (
	"errors"
)

var ErrImageDoesNotExist = errors.New("image does not exist")

// ImageBackend is a consumer-focused abstraction that describes the needs of the admission controller with respect
// to Anchore image-related API operations.
type ImageBackend interface {
	Get(asUser Credential, imageReference string) (Image, error)
	Analyze(asUser Credential, imageReference string) error
	DoesPolicyCheckPass(asUser Credential, imageDigest, imageTag, policyBundleID string) (bool, error)
}
