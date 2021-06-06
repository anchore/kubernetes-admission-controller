package anchore

import (
	"errors"

	"k8s.io/klog"
)

var ErrImageDoesNotExist = errors.New("image does not exist")

// ImageBackend is a consumer-focused abstraction that describes the needs of the admission controller with respect
// to Anchore image-related API operations.
type ImageBackend interface {
	Get(imageReference string) (Image, error)
	Analyze(imageReference string) error
	DoesPolicyCheckPass(imageDigest, imageTag, policyBundleID string) (bool, error)
}

// GetImageBackend returns an abstract ImageBackend with an underlying implementation for fulfilling Anchore image
// -related API requests.
func GetImageBackend(authConfig AuthConfiguration, user, endpoint string) ImageBackend {
	klog.Infof("looking for Anchore user %q among configured credentials", user)

	for _, entry := range authConfig.Users {
		if entry.Username == user {
			klog.Infof("found credentials for user %q! creating an Anchore image client", user)
			return newAnchoreAPIImageBackend(entry.Username, entry.Password, endpoint)
		}
	}

	klog.Infof("user %q not found among configured credentials", user)

	return nil
}
