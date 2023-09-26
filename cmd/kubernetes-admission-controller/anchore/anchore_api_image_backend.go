package anchore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	anchoreEnterprise "github.com/anchore/enterprise-client-go/pkg/enterprise"
	"k8s.io/klog"
)

type APIImageBackend struct {
	client imagesClient
}

func NewAPIImageBackend(endpoint string) (APIImageBackend, error) {
	cfg := anchoreEnterprise.NewConfiguration()
	cfg.UserAgent = fmt.Sprintf("AnchoreAdmissionController-%s", cfg.UserAgent)
	cfg.Servers = anchoreEnterprise.ServerConfigurations{
		{
			URL: fmt.Sprintf("%s/v2", endpoint),
		},
	}

	// TODO: cert verification options?
	client := anchoreEnterprise.NewAPIClient(cfg)

	// Check the API Version, error if version is not 2 or no version is returned.
	// In version 1 of the API the version is returned empty.
	versionCheckRequest := client.DefaultApi.VersionCheck(context.Background())
	ver, _, err := versionCheckRequest.Execute()
	if err != nil {
		return APIImageBackend{}, err
	}
	if !ver.Api.HasVersion() {
		return APIImageBackend{}, fmt.Errorf("no API version found")
	}
	if *ver.Api.Version != "2" {
		return APIImageBackend{}, fmt.Errorf("found API version %q not version 2", *ver.Api.Version)
	}

	return APIImageBackend{
		client: client.ImagesApi,
	}, nil
}

func (p APIImageBackend) Get(asUser Credential, imageReference string) (Image, error) {
	klog.Infof("getting image %q from Anchore", imageReference)

	// Find the latest image with this tag
	ctx := authContextFromCredential(asUser)
	imageList, _, err := p.client.ListImages(ctx).FullTag(imageReference).Execute()
	images := imageList.GetItems()
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

	imageTagSource := anchoreEnterprise.NewRegistryTagSource(imageReference)
	imageSource := anchoreEnterprise.NewImageSource()
	imageSource.SetTag(*imageTagSource)

	request := *anchoreEnterprise.NewImageAnalysisRequest()
	request.SetAnnotations(annotations)
	request.SetSource(*imageSource)

	ctx := authContextFromCredential(asUser)
	image, _, err := p.client.AddImage(ctx).Image(request).AutoSubscribe(false).Execute()
	if err != nil {
		return err
	}

	klog.Info(
		fmt.Sprintf("image analysis for image %q requested and found mapped to digest %q", imageReference,
			*image.ImageDigest),
	)

	return nil
}

func (p APIImageBackend) DoesPolicyCheckPass(asUser Credential, imageDigest, imageTag, policyBundleID string) (bool, error) {
	ctx := authContextFromCredential(asUser)
	var err error
	var evaluation interface{}
	if policyBundleID != "" {
		evaluation, _, err = p.client.GetImagePolicyCheckByDigest(ctx, imageDigest).
			Tag(imageTag).
			Interactive(true).
			PolicyId(policyBundleID).
			Execute()
	} else {
		evaluation, _, err = p.client.GetImagePolicyCheckByDigest(ctx, imageDigest).Tag(imageTag).Interactive(true).Execute()
	}
	if err != nil {
		return false, err
	}

	var resultStatus string
	resultMap, ok := evaluation.(anchoreEnterprise.PolicyEvaluation)
	if ok {
		resultStatus = getPolicyEvaluationStatus(resultMap.Evaluations)
	}
	return strings.ToLower(resultStatus) == "pass", nil
}

func getPolicyEvaluationStatus(policyEvaluations *[]anchoreEnterprise.PolicyEvaluationEvaluations) string {
	// Immediately fail if any policy evaluation fails
	status := ""
	for _, evaluation := range *policyEvaluations {
		status = evaluation.Status
		if strings.ToLower(status) == "fail" {
			return status
		}
	}

	return status
}

func authContextFromCredential(credential Credential) context.Context {
	basicAuthValues := anchoreEnterprise.BasicAuth{
		UserName: credential.Username,
		Password: credential.Password,
	}

	return context.WithValue(context.Background(), anchoreEnterprise.ContextBasicAuth, basicAuthValues)
}
