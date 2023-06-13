package anchore

import (
	"context"

	anchoreEngine "github.com/anchore/enterprise-client-go/pkg/engine"
)

// imagesClient abstracts the Anchore Go client's images service and exposes
// only the client operations needed by this application.
type imagesClient interface {
	AddImage(
		ctx context.Context,
	) anchoreEngine.ApiAddImageRequest
	ListImages(
		ctx context.Context,
	) anchoreEngine.ApiListImagesRequest
	GetImagePolicyCheck(
		ctx context.Context,
		imageDigest string,
	) anchoreEngine.ApiGetImagePolicyCheckRequest
}
