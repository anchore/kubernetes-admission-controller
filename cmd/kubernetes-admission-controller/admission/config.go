package admission

import "github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"

type ControllerConfiguration struct {
	Validator       ValidatorConfiguration
	AnchoreEndpoint string // The full url to use for interacting with anchore
	PolicySelectors []validation.PolicySelector
}
