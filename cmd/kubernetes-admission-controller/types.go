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

// The key is the endpoint, username tuple
type AnchoreCredential struct {
	//Endpoint string
	Username string
	Password string
}

type ValidatorConfiguration struct {
	Enabled              bool
	RequireImageAnalyzed bool
	RequirePassPolicy    bool
	RequestAnalysis      bool
}

// Maps an endpoint, user tuple to a policy bundle. The bundle must exist on the engine addressed by the endpoint.
type AnchoreClientConfiguration struct {
	//Endpoint       string
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
}

type SelectorResourceType string

const (
	PodSelectorType       SelectorResourceType = "pod"
	NamespaceSelectorType SelectorResourceType = "namespace"
	ImageSelectorType     SelectorResourceType = "image"
)

//type CompiledSelector struct {
//	resType SelectorResourceType
//	keyRegex regexp.Regexp
//	valueRegex regexp.Regexp
//}

