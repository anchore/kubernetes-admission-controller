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

type anchoreAPIImageBackend struct {
	client imagesClient
	auth   context.Context
}

func newAnchoreAPIImageBackend(username, password, endpoint string) anchoreAPIImageBackend {
	cfg := anchore.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.BasePath = endpoint

	// TODO: cert verification options?
	client := anchore.NewAPIClient(cfg)

	// TODO: context timeouts
	auth := context.WithValue(context.Background(), anchore.ContextBasicAuth, anchore.BasicAuth{UserName: username, Password: password})

	return anchoreAPIImageBackend{
		client: client.ImagesApi,
		auth:   auth,
	}
}

func (p anchoreAPIImageBackend) Get(imageReference string) (Image, error) {
	localOptions := anchore.ListImagesOpts{}
	localOptions.Fulltag = optional.NewString(imageReference)
	klog.Infof("getting image %q from Anchore", imageReference)

	// Find the latest image with this tag
	images, _, err := p.client.ListImages(p.auth, &localOptions)
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

	sort.Slice(images, func(i int, j int) bool {
		return images[i].CreatedAt.Before(images[j].CreatedAt)
	})

	image := images[0]

	klog.Infof("image found for %q (status: %q, digest: %q)", imageReference, image.AnalysisStatus, image.ImageDigest)

	return Image{
		Digest:         image.ImageDigest,
		AnalysisStatus: image.AnalysisStatus,
	}, nil
}

func (p anchoreAPIImageBackend) Analyze(imageReference string) error {
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

func (p anchoreAPIImageBackend) DoesPolicyCheckPass(imageDigest, imageTag, policyBundleID string) (bool, error) {
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
