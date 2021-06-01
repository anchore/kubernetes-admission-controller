/*
Type definitions for the controller
*/

package main

import (
	_context "context"
	_nethttp "net/http"

	anchore "github.com/anchore/kubernetes-admission-controller/pkg/anchore/client"
)

type ControllerConfiguration struct {
	Validator       ValidatorConfiguration
	AnchoreEndpoint string // The full url to use for interacting with anchore

	PolicySelectors []PolicySelector
}

type AnchoreAuthConfig struct {
	Users []AnchoreCredential
}

type AnchoreCredential struct {
	Username string
	Password string
}

type ValidatorConfiguration struct {
	Enabled bool
	//RequireImageAnalyzed bool
	//RequirePassPolicy    bool
	RequestAnalysis bool
}

type AnchoreClientConfiguration struct {
	Username       string
	PolicyBundleId string
}

type ResourceSelector struct {
	ResourceType       SelectorResourceType // The resource to do selection on, supported: pod, namespace
	SelectorKeyRegex   string               // The regex to select a matching key
	SelectorValueRegex string               // The regex to apply to the label/annotation of the specified resource type
}

type PolicySelector struct {
	ResourceSelector ResourceSelector
	PolicyReference  AnchoreClientConfiguration
	Mode             GateModeType
}

type SelectorResourceType string
type GateModeType string

type GateConfiguration struct {
	Mode            GateModeType
	PolicyReference AnchoreClientConfiguration
}

// anchoreImagesClient is an abstraction for consumers that need to interact with Anchore's image functionality.
type anchoreImagesClient interface {
	AddImage(
		ctx _context.Context,
		image anchore.ImageAnalysisRequest,
		localVarOptionals *anchore.AddImageOpts,
	) ([]anchore.AnchoreImage, *_nethttp.Response, error)
	ListImages(
		ctx _context.Context,
		localVarOptionals *anchore.ListImagesOpts,
	) ([]anchore.AnchoreImage, *_nethttp.Response, error)
	GetImagePolicyCheck(
		ctx _context.Context,
		imageDigest string,
		tag string,
		localVarOptionals *anchore.GetImagePolicyCheckOpts,
	) ([]map[string]interface{}, *_nethttp.Response, error)
}

const (
	ResourceSelectorType  SelectorResourceType = "resource"
	PodSelectorType       SelectorResourceType = "pod"
	NamespaceSelectorType SelectorResourceType = "namespace"
	ImageSelectorType     SelectorResourceType = "image"
	PolicyGateMode        GateModeType         = "policy"
	AnalysisGateMode      GateModeType         = "analysis"
	BreakGlassMode        GateModeType         = "breakglass"
)
