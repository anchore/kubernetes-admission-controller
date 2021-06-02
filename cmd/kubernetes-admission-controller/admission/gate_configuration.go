package admission

import (
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

type GateConfiguration struct {
	Mode            validation.Mode
	PolicyReference anchore.ClientConfiguration
}

func determineGateConfiguration(
	meta metav1.ObjectMeta,
	imageReference string,
	policySelectors []PolicySelector,
	clientset kubernetes.Clientset,
) *GateConfiguration {
	for _, policySelector := range policySelectors {
		klog.Info("Checking selector ", "selector=", policySelector)

		selectedObjectMeta := selectObjectMetaForMatching(policySelector.ResourceSelector.Type, meta, clientset)

		if selectedObjectMeta != nil {
			if match := doesObjectMatchResourceSelector(selectedObjectMeta, policySelector.ResourceSelector); match {
				klog.Info("Matched selector rule=", policySelector)

				return &GateConfiguration{
					Mode:            policySelector.Mode,
					PolicyReference: policySelector.PolicyReference,
				}
			}
		} else {
			if match := doesMatchImageResource(policySelector.ResourceSelector.SelectorValueRegex, imageReference); match {
				klog.Info("Matched selector rule=", policySelector, " with mode=", policySelector.Mode)

				return &GateConfiguration{
					Mode:            policySelector.Mode,
					PolicyReference: policySelector.PolicyReference,
				}
			}
		}
	}

	return nil
}

// selectObjectMetaForMatching gets the correct set of ObjectMeta for comparison,
// or nil if not a selector that uses ObjectMeta.
func selectObjectMetaForMatching(resourceSelectorType ResourceSelectorType, objectMeta metav1.ObjectMeta, clientset kubernetes.Clientset) *metav1.ObjectMeta {
	klog.Info("Resolving the resource to use for selection")
	switch resourceSelectorType {
	case GeneralResourceSelectorType:
		return &objectMeta
	case NamespaceResourceSelectorType:
		namespace, err := clientset.CoreV1().Namespaces().Get(objectMeta.Namespace, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
			return nil
		}

		return &namespace.ObjectMeta
	case ImageResourceSelectorType:
		return nil
	default:
		return nil
	}
}
