package validation

import (
	"fmt"
	"strings"
)

// Result is a data structure that describes the evaluation result for a validation operation.
type Result struct {
	Mode        Mode
	IsValid     bool
	Message     string
	ImageDigest string
}

// Reduce takes an arbitrary number of Results as input and reduces them to a single Result.
// This Result's Message aggregates the input Results' Messages, prefixed with the given messagePrefix.
// If only a single Result is passed in, the Result is returned as-is (and the messagePrefix is not used).
func Reduce(results []Result, messagePrefix string) Result {
	if len(results) == 1 {
		return results[0]
	}

	var messageComponents []string
	isValid := true

	for _, result := range results {
		if !result.IsValid {
			isValid = false
		}

		var messageSuffixes []string

		if result.Mode != "" {
			messageSuffixes = append(messageSuffixes, fmt.Sprintf("mode: %s", result.Mode))
		}
		if result.ImageDigest != "" {
			messageSuffixes = append(messageSuffixes, fmt.Sprintf("digest: %s", result.ImageDigest))
		}

		messageSuffix := ""

		if len(messageSuffixes) >= 1 {
			messageSuffix = fmt.Sprintf(" (%s)", strings.Join(messageSuffixes, ","))
		}

		messageComponents = append(messageComponents, result.Message+messageSuffix)
	}

	return Result{
		IsValid: isValid,
		Message: fmt.Sprintf("%s [ %s ]", messagePrefix, strings.Join(messageComponents, "; ")),
	}
}
