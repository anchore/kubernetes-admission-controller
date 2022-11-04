package validation

import (
	"context"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"time"
)

type Configuration struct {
	Mode            Mode
	PolicyReference anchore.PolicyReference
}

func NewConfiguration(
	meta metav1.ObjectMeta,
	imageReference string,
	policySelectors []PolicySelector,
	clientset kubernetes.Clientset,
) *Configuration {
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

				return &Configuration{
					Mode:            policySelector.Mode,
					PolicyReference: policySelector.PolicyReference,
				}
			}
		} else {
			klog.Info("no object meta selected")

			if match := doesMatchImageResource(policySelector.ResourceSelector.SelectorValueRegex, imageReference); match {
				klog.Infof("image reference %q matched policy selector", imageReference)

				return &Configuration{
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
	klog.Infof("resolving the resource to use for selection (type: %s)", resourceSelectorType)

	switch resourceSelectorType {
	case GeneralResourceSelectorType:
		return &objectMeta
	case NamespaceResourceSelectorType:
		ctx, cancel_fn := context.WithTimeout(context.TODO(), 5*time.Second)
		defer cancel_fn()
		namespace, err := clientset.CoreV1().Namespaces().Get(ctx, objectMeta.Namespace, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
			return nil
		}

		if namespace != nil {
			return &namespace.ObjectMeta
		} else {
			klog.Warningf("could not get a namespace information for %s", objectMeta.Namespace)
			return nil
		}
	case ImageResourceSelectorType:
		return nil
	default:
		return nil
	}
}
