package validation

import "k8s.io/klog"

// breakGlass returns a Result for the "break glass" gate mode (and performs no actual validation).
// The Result is always valid!
func breakGlass() Result {
	message := "no check requirements in config"
	klog.Info(message)

	return Result{
		Mode:    BreakGlassMode,
		IsValid: true,
		Message: message,
	}
}
