package anchore

import (
	"context"

	anchoreEngine "github.com/anchore/enterprise-client-go-v1/pkg/engine"
	anchoreEnterprise "github.com/anchore/enterprise-client-go/pkg/enterprise"
)

// imagesClient abstracts the Anchore Go client's images service and exposes
// only the client operations needed by this application.
type imagesClientV1 interface {
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

type imagesClient interface {
	AddImage(
		ctx context.Context,
	) anchoreEnterprise.ApiAddImageRequest
	ListImages(
		ctx context.Context,
	) anchoreEnterprise.ApiListImagesRequest
	GetImagePolicyCheckByDigest(
		ctx context.Context,
		imageDigest string,
	) anchoreEnterprise.ApiGetImagePolicyCheckByDigestRequest
}
