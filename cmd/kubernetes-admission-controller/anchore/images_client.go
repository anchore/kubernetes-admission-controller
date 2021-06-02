package anchore

import (
	"context"
	_nethttp "net/http"

	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
)

// imagesClient abstracts the Anchore Go client and exposes only the client operations needed by this application.
type imagesClient interface {
	AddImage(
		ctx context.Context,
		image anchore.ImageAnalysisRequest,
		localVarOptionals *anchore.AddImageOpts,
	) ([]anchore.AnchoreImage, *_nethttp.Response, error)
	ListImages(
		ctx context.Context,
		localVarOptionals *anchore.ListImagesOpts,
	) ([]anchore.AnchoreImage, *_nethttp.Response, error)
	GetImagePolicyCheck(
		ctx context.Context,
		imageDigest string,
		tag string,
		localVarOptionals *anchore.GetImagePolicyCheckOpts,
	) ([]map[string]interface{}, *_nethttp.Response, error)
}
