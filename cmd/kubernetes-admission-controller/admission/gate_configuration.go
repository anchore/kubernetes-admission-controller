package admission

import (
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

type gateConfiguration struct {
	mode            validation.Mode
	policyReference anchore.PolicyReference
}

func determineGateConfiguration(
	meta metav1.ObjectMeta,
	imageReference string,
	policySelectors []PolicySelector,
	clientset kubernetes.Clientset,
) *gateConfiguration {
	klog.Infof("determining gate configuration for image %q, found %d policy selectors", imageReference,
		len(policySelectors))
	klog.Infof("object metadata: %+v", meta)

	for i, policySelector := range policySelectors {
		klog.Infof("checking policy selector at index %d: %+v", i, policySelector)

		selectedObjectMeta := selectObjectMetaForMatching(policySelector.ResourceSelector.Type, meta, clientset)

		if selectedObjectMeta != nil {
			klog.Infof("object meta selected (name: %q)", selectedObjectMeta.Name)

			if match := doesObjectMatchResourceSelector(selectedObjectMeta, policySelector.ResourceSelector); match {
				klog.Infof("matched policy selector: %+v", policySelector)

				return &gateConfiguration{
					mode:            policySelector.Mode,
					policyReference: policySelector.PolicyReference,
				}
			}
		} else {
			klog.Info("no object meta selected")

			if match := doesMatchImageResource(policySelector.ResourceSelector.SelectorValueRegex, imageReference); match {
				klog.Infof("image reference %q matched policy selector", imageReference)

				return &gateConfiguration{
					mode:            policySelector.Mode,
					policyReference: policySelector.PolicyReference,
				}
			}
		}
	}

	return nil
}

// selectObjectMetaForMatching gets the correct set of ObjectMeta for comparison,
// or nil if not a selector that uses ObjectMeta.
func selectObjectMetaForMatching(resourceSelectorType ResourceSelectorType, objectMeta metav1.ObjectMeta, clientset kubernetes.Clientset) *metav1.ObjectMeta {
	klog.Infof("resolving the resource to use for selection (type: %s)", resourceSelectorType)

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
