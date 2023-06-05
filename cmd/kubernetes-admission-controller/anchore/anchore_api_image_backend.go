package anchore

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	anchoreEngine "github.com/anchore/enterprise-client-go/pkg/engine"
	"k8s.io/klog"
)

type APIImageBackend struct {
	client imagesClient
}

func NewAPIImageBackend(endpoint string) APIImageBackend {
	cfg := anchoreEngine.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.Servers = anchoreEngine.ServerConfigurations{
		{
			URL: endpoint,
		},
	}

	// TODO: cert verification options?
	client := anchoreEngine.NewAPIClient(cfg)

	return APIImageBackend{
		client: client.ImagesApi,
	}
}

func (p APIImageBackend) Get(asUser Credential, imageReference string) (Image, error) {
	klog.Infof("getting image %q from Anchore", imageReference)

	// Find the latest image with this tag
	ctx := authContextFromCredential(asUser)
	images, _, err := p.client.ListImages(ctx).Fulltag(imageReference).Execute()
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
		return images[i].CreatedAt.Before(*images[j].CreatedAt)
	})

	image := images[0]

	klog.Infof("image found for %q (status: %q, digest: %q)", imageReference, *image.AnalysisStatus, *image.ImageDigest)

	return Image{
		Digest:         *image.ImageDigest,
		AnalysisStatus: *image.AnalysisStatus,
	}, nil
}

func (p APIImageBackend) Analyze(asUser Credential, imageReference string) error {
	annotations := make(map[string]interface{})
	annotations["requestor"] = "anchore-admission-controller"

	imageTagSource := anchoreEngine.NewRegistryTagSource(imageReference)
	imageSource := anchoreEngine.NewImageSource()
	imageSource.SetTag(*imageTagSource)

	request := *anchoreEngine.NewImageAnalysisRequest()
	request.SetAnnotations(annotations)
	request.SetSource(*imageSource)
	request.SetCreatedAt(time.Now().UTC().Round(time.Second))

	ctx := authContextFromCredential(asUser)
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

func (p APIImageBackend) DoesPolicyCheckPass(asUser Credential, imageDigest, imageTag, policyBundleID string) (bool, error) {
	ctx := authContextFromCredential(asUser)
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
			resultStatus = getPolicyEvaluationStatus(resultMap)
		}
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

func authContextFromCredential(credential Credential) context.Context {
	basicAuthValues := anchoreEngine.BasicAuth{
		UserName: credential.Username,
		Password: credential.Password,
	}

	return context.WithValue(context.Background(), anchoreEngine.ContextBasicAuth, basicAuthValues)
}
