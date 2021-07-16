package admission

import "github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"

type ControllerConfiguration struct {
	Validator ValidatorConfiguration

	AnchoreEndpoint string // The full url to use for interacting with anchore.
	// TODO: This is no longer used beyond the ImageBackend injection into the Hook,
	//  so this field doesn't need to be passed into the Hook via any other method.
	//  NOTE: This is a user-facing config change.

	PolicySelectors []validation.PolicySelector
}
