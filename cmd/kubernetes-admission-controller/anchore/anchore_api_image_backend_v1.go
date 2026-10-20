package anchore

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	anchoreEngine "github.com/anchore/enterprise-client-go-v1/pkg/engine"
	"k8s.io/klog"
)

type APIImageBackendV1 struct {
	client imagesClientV1
}

func NewAPIImageBackendV1(endpoint string) (APIImageBackendV1, error) {
	cfg := anchoreEngine.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.Servers = anchoreEngine.ServerConfigurations{
		{
			URL: endpoint,
		},
	}

	// TODO: cert verification options?
	client := anchoreEngine.NewAPIClient(cfg)

	versionCheckRequest := client.DefaultApi.VersionCheck(context.Background())
	ver, _, err := versionCheckRequest.Execute()
	if err != nil {
		return APIImageBackendV1{}, err
	}
	// For v1 API the api struct is returned empty
	if ver.Api.HasVersion() {
		return APIImageBackendV1{}, fmt.Errorf("found API version %q not version 1", *ver.Api.Version)
	}

	return APIImageBackendV1{
		client: client.ImagesApi,
	}, nil
}

func (p APIImageBackendV1) Get(asUser Credential, imageReference string) (Image, error) {
	klog.Infof("getting image %q from Anchore", imageReference)

	ref := parseImageReference(imageReference)
	ctx := authContextFromCredentialV1(asUser)

	if ref.isDigestPinned() {
		image, found, err := p.getByDigest(ctx, ref)
		if err != nil {
			klog.Errorf("error retrieving image %q from Anchore: %v", imageReference, err)
			return Image{}, err
		}
		if found {
			klog.Infof("image found for %q (status: %q, digest: %q)", imageReference, image.AnalysisStatus, image.Digest)
			return image, nil
		}
		// The pinned digest can be a multi-platform manifest list digest, which Anchore stores as the parent
		// digest of the platform-specific image and does not look up directly, so fall back to the tag's images.
	}

	// Find the latest image with this tag
	listRequest := p.client.ListImages(ctx).Fulltag(ref.tag)
	if ref.isDigestPinned() {
		// Include images the tag pointed to earlier, so a pinned digest is found after the tag moves on.
		listRequest = listRequest.History(true)
	}
	images, _, err := listRequest.Execute()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			klog.Infof("image %q not found in Anchore", imageReference)
			return Image{}, ErrImageDoesNotExist
		}

		klog.Errorf("error retrieving image %q from Anchore: %v", imageReference, err)
		return Image{}, err
	}

	if len(images) == 0 {
		return Image{}, fmt.Errorf("no images found with tag %q", imageReference)
	}

	// A digest-pinned reference only matches the image with that digest, not whatever the tag points to now.
	if ref.isDigestPinned() {
		var pinned []anchoreEngine.AnchoreImage
		for _, image := range images {
			if ref.matchesDigest(image.ImageDigest, image.ParentDigest) {
				pinned = append(pinned, image)
			}
		}
		if len(pinned) == 0 {
			klog.Infof("image %q not found in Anchore", imageReference)
			return Image{}, ErrImageDoesNotExist
		}
		images = pinned
	}

	sort.Slice(images, func(i int, j int) bool {
		return images[i].CreatedAt.Before(*images[j].CreatedAt)
	})

	image := images[0]

	klog.Infof("image found for %q (status: %q, digest: %q)", imageReference, *image.AnalysisStatus, *image.ImageDigest)

	return Image{
		Digest:         *image.ImageDigest,
		AnalysisStatus: *image.AnalysisStatus,
	}, nil
}

// getByDigest looks up the image whose digest is the reference's pinned digest, regardless of which tag it was
// analyzed under. It reports found as false when Anchore has no image with that digest.
func (p APIImageBackendV1) getByDigest(ctx context.Context, ref imageReference) (Image, bool, error) {
	images, _, err := p.client.GetImage(ctx, ref.digest).Execute()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			return Image{}, false, nil
		}
		return Image{}, false, err
	}
	if len(images) == 0 {
		return Image{}, false, nil
	}

	return Image{
		Digest:         images[0].GetImageDigest(),
		AnalysisStatus: images[0].GetAnalysisStatus(),
	}, true, nil
}

func (p APIImageBackendV1) Analyze(asUser Credential, imageReference string) error {
	annotations := make(map[string]interface{})
	annotations["requestor"] = "anchore-admission-controller"

	ref := parseImageReference(imageReference)
	imageSource := anchoreEngine.NewImageSource()
	if ref.isDigestPinned() {
		imageSource.SetDigest(*anchoreEngine.NewRegistryDigestSource(ref.digestPullString(), ref.tag))
	} else {
		imageSource.SetTag(*anchoreEngine.NewRegistryTagSource(imageReference))
	}

	request := *anchoreEngine.NewImageAnalysisRequest()
	request.SetAnnotations(annotations)
	request.SetSource(*imageSource)
	request.SetCreatedAt(time.Now().UTC().Round(time.Second))

	ctx := authContextFromCredentialV1(asUser)
	images, _, err := p.client.AddImage(ctx).Image(request).Autosubscribe(false).Execute()
	if err != nil {
		return err
	}

	if len(images) == 0 {
		return fmt.Errorf("no image record received in successful response to image add request for %q", imageReference)
	}

	image := images[0]

	klog.Info(
		fmt.Sprintf("image analysis for image %q requested and found mapped to digest %q", imageReference,
			*image.ImageDigest),
	)

	return nil
}

func (p APIImageBackendV1) DoesPolicyCheckPass(asUser Credential, imageDigest, imageTag, policyBundleID string) (bool, error) {
	imageTag = parseImageReference(imageTag).tag
	ctx := authContextFromCredentialV1(asUser)
	var err error
	var evaluations []interface{}
	if policyBundleID != "" {
		evaluations, _, err = p.client.GetImagePolicyCheck(ctx, imageDigest).
			Tag(imageTag).
			Interactive(true).
			PolicyId(policyBundleID).
			Execute()
	} else {
		evaluations, _, err = p.client.GetImagePolicyCheck(ctx, imageDigest).Tag(imageTag).Interactive(true).Execute()
	}
	if err != nil {
		return false, err
	}

	if len(evaluations) > 0 {
		var resultStatus string
		if resultMap, ok := evaluations[0].(map[string]interface{}); ok {
			resultStatus = getPolicyEvaluationStatusV1(resultMap)
		}
		return strings.ToLower(resultStatus) == "pass", nil
	}

	return false, nil
}

func getPolicyEvaluationStatusV1(policyEvaluation map[string]interface{}) string {
	// Looks through a parsed result for the status value, assumes this result is for a single image
	digest := reflect.ValueOf(policyEvaluation).MapKeys()[0].String()
	tag := reflect.ValueOf(policyEvaluation[digest]).MapKeys()[0]

	result := reflect.ValueOf(reflect.ValueOf(policyEvaluation[digest]).MapIndex(tag).Interface()).Index(0).Elem()
	for _, key := range result.MapKeys() {
		if key.String() == "status" {
			statusValue := result.MapIndex(key)
			status := fmt.Sprintf("%s", statusValue)
			return status
		}
	}

	return ""
}

func authContextFromCredentialV1(credential Credential) context.Context {
	basicAuthValues := anchoreEngine.BasicAuth{
		UserName: credential.Username,
		Password: credential.Password,
	}

	return context.WithValue(context.Background(), anchoreEngine.ContextBasicAuth, basicAuthValues)
}
