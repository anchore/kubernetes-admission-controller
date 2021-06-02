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
	objectMeta metav1.ObjectMeta,
	imageReference string,
	config ControllerConfiguration,
	clientset kubernetes.Clientset,
) *GateConfiguration {
	for _, policySelector := range config.PolicySelectors {
		klog.Info("Checking selector ", "selector=", policySelector)

		meta, err := selectObjectMetaForMatching(policySelector.ResourceSelector, objectMeta, clientset)
		if err != nil {
			klog.Error("Error checking selector, skipping err=", err)
			continue
		}

		if meta != nil {
			if match := doesObjectMatchResourceSelector(meta, policySelector.ResourceSelector); match {
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
func selectObjectMetaForMatching(selector ResourceSelector, objectMeta metav1.ObjectMeta,
	clientset kubernetes.Clientset) (*metav1.ObjectMeta,
	error) {
	klog.Info("Resolving the resource to use for selection")
	switch selector.ResourceType {
	case GeneralResourceSelectorType:
		return &objectMeta, nil
	case NamespaceResourceSelectorType:
		nsFound, err := clientset.CoreV1().Namespaces().Get(objectMeta.Namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		return &nsFound.ObjectMeta, nil
	case ImageResourceSelectorType:
		return nil, nil
	default:
		return nil, nil
	}
}
