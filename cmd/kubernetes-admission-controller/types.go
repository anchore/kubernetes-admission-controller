/*
Type definitions for the controller
*/

package main

type ControllerConfiguration struct {
	Validator ValidatorConfiguration
	AnchoreEndpoint  string // The full url to use for interacting with anchore

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
	Enabled              bool
	//RequireImageAnalyzed bool
	//RequirePassPolicy    bool
	RequestAnalysis      bool
}

type AnchoreClientConfiguration struct {
	Username       string
	PolicyBundleId string
}

type ResourceSelector struct {
	ResourceType    SelectorResourceType // The resource to do selection on, supported: pod, namespace
	SelectorKeyRegex string // The regex to select a matching key
	SelectorValueRegex   string // The regex to apply to the label/annotation of the specified resource type
}

type PolicySelector struct {
	Selector ResourceSelector
	PolicyReference AnchoreClientConfiguration
	Mode GateModeType
}

type SelectorResourceType string
type GateModeType string

const (
	PodSelectorType       SelectorResourceType = "pod"
	NamespaceSelectorType SelectorResourceType = "namespace"
	ImageSelectorType     SelectorResourceType = "image"
	PolicyGateMode        GateModeType = "policy"
	AnalysisGateMode      GateModeType = "analysis"
	BreakGlassMode        GateModeType = "breakglass"
)


