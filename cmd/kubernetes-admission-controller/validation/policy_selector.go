package validation

import (
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
)

type PolicySelector struct {
	ResourceSelector ResourceSelector `mapstructure:"Selector"`
	Mode             Mode
	PolicyReference  anchore.PolicyReference
}
