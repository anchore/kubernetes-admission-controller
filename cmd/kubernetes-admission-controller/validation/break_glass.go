package validation

import "k8s.io/klog"

// BreakGlass returns a Result for the "break glass" gate mode (and performs no actual validation).
// The Result is always valid.
func BreakGlass() Result {
	message := "no check requirements in config"
	klog.Info(message)

	return Result{
		IsValid: true,
		Message: message,
	}
}
