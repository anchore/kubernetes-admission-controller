package anchore

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
	"github.com/antihax/optional"
	"k8s.io/klog"
)

type authenticatedImageProvider struct {
	client imagesClient
	auth   context.Context
}

func newAuthenticatedImageProvider(username, password, endpoint string) authenticatedImageProvider {
	cfg := anchore.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.BasePath = endpoint

	// TODO: cert verification options?
	client := anchore.NewAPIClient(cfg)

	// TODO: context timeouts
	auth := context.WithValue(context.Background(), anchore.ContextBasicAuth, anchore.BasicAuth{UserName: username, Password: password})

	return authenticatedImageProvider{
		client: client.ImagesApi,
		auth:   auth,
	}
}

func (p authenticatedImageProvider) Get(imageReference string) (Image, error) {
	localOptions := anchore.ListImagesOpts{}
	localOptions.Fulltag = optional.NewString(imageReference)
	klog.Info("Getting image from anchore engine. Reference=", imageReference)

	// Find the latest image with this tag
	images, _, err := p.client.ListImages(p.auth, &localOptions)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "404 not found") {
			return Image{}, ErrImageDoesNotExist
		}

		return Image{}, err
	}

	klog.Info("Getting image")
	if len(images) == 0 {
		return Image{}, fmt.Errorf("no images found with tag %q", imageReference)
	}

	sort.Slice(images, func(i int, j int) bool {
		return images[i].CreatedAt.Before(images[j].CreatedAt)
	})

	image := images[0]

	return Image{
		Digest:         image.ImageDigest,
		AnalysisStatus: image.AnalysisStatus,
	}, nil
}

func (p authenticatedImageProvider) Analyze(imageReference string) error {
	annotations := make(map[string]interface{})
	annotations["requestor"] = "anchore-admission-controller"

	opts := anchore.AddImageOpts{}
	opts.Autosubscribe = optional.NewBool(false)

	req := anchore.ImageAnalysisRequest{
		Tag:         imageReference,
		Annotations: annotations,
		CreatedAt:   time.Now().UTC().Round(time.Second),
	}

	images, _, err := p.client.AddImage(p.auth, req, &opts)

	if err != nil {
		return err
	}

	if len(images) == 0 {
		return fmt.Errorf("no image record received in successful response to image add request for %q", imageReference)
	}

	image := images[0]

	klog.Info(
		fmt.Sprintf("image analysis for image %q requested and found mapped to digest %q", imageReference,
			image.ImageDigest),
	)

	return nil
}

func (p authenticatedImageProvider) DoesPolicyCheckPass(imageDigest, imageTag, policyBundleID string) (bool, error) {
	localOptions := anchore.GetImagePolicyCheckOpts{}
	localOptions.Interactive = optional.NewBool(true)
	if policyBundleID != "" {
		localOptions.PolicyId = optional.NewString(policyBundleID)
	}

	evaluations, _, err := p.client.GetImagePolicyCheck(p.auth, imageDigest, imageTag, &localOptions)
	if err != nil {
		return false, err
	}

	if len(evaluations) > 0 {
		resultStatus := getPolicyEvaluationStatus(evaluations[0])
		return strings.ToLower(resultStatus) == "pass", nil
	}

	return false, nil
}

func getPolicyEvaluationStatus(policyEvaluation map[string]interface{}) string {
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

const goodPassResponse = `
[
  {
    "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b": {
      "docker.io/alpine:latest": [
        {
          "detail": {},
          "last_evaluation": "2018-12-03T17:46:13Z",
          "policyId": "2c53a13c-1765-11e8-82ef-23527761d060",
          "status": "pass"
        }
      ]
    }
  }
]
`
