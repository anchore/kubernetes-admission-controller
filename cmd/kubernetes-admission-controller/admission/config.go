package admission

type ControllerConfiguration struct {
	Validator       ValidatorConfiguration
	AnchoreEndpoint string // The full url to use for interacting with anchore
	PolicySelectors []PolicySelector
}
