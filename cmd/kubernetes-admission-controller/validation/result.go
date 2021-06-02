package validation

// Result is a data structure that describes the evaluation result for a validation operation.
type Result struct {
	Mode        Mode
	IsValid     bool
	Message     string
	ImageDigest string
}
