package validation

import (
	"errors"
	"fmt"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
)

// Validator is a function that can be executed to produce a validation Result.
type Validator func() Result

// New returns a validator function with its internal state fully configured.
// If a validator function cannot be created, New returns an error.
func New(configuration Configuration, imageBackend anchore.ImageBackend, user anchore.Credential,
	imageReference string) (Validator, error) {
	switch mode := configuration.Mode; mode {
	case PolicyGateMode:
		return func() Result {
			return policy(imageBackend, user, imageReference, configuration.PolicyReference.PolicyBundleId)
		}, nil

	case AnalysisGateMode:
		return func() Result {
			return analysis(imageBackend, user, imageReference)
		}, nil

	case BreakGlassMode:
		return breakGlass, nil

	default:
		message := fmt.Sprintf("got unexpected value %q for validation mode from matching selector", mode)
		return nil, errors.New(message)
	}
}
