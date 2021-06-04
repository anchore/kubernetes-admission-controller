package admission

import (
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type ResourceSelector struct {
	Type ResourceSelectorType // The resource to do selection on,
	// supported: pod, namespace
	SelectorKeyRegex   string // The regex to select a matching key
	SelectorValueRegex string // The regex to apply to the label/annotation of the specified resource type
}

func doesObjectMatchResourceSelector(object *metav1.ObjectMeta, resourceSelector ResourceSelector) bool {
	klog.Infof("testing match of object %q for resource selector: %+v", object, resourceSelector)

	mapArray := []map[string]string{object.Labels, object.Annotations}
	for _, kvMap := range mapArray {
		for k, v := range kvMap {
			if doesKeyValuePairMatchResourceSelector(k, v, resourceSelector) {
				klog.Infof("matched key %q to value %q", k, v)
				return true
			}
		}
	}

	// Treat Name specially
	if strings.ToLower(resourceSelector.SelectorKeyRegex) == "name" {
		doesSelectorMatchName, err := regexp.MatchString(resourceSelector.SelectorValueRegex, object.Name)
		if err != nil {
			klog.Errorf("failed evaluating regex pattern %q against metadata name %q: %v",
				resourceSelector.SelectorKeyRegex, object.Name, err)
		}
		return doesSelectorMatchName
	}

	return false
}

func doesKeyValuePairMatchResourceSelector(key, value string, resourceSelector ResourceSelector) bool {
	doesMatch, err := regexp.MatchString(resourceSelector.SelectorKeyRegex, key)
	if err != nil {
		klog.Errorf("Error evaluating regex pattern %q for selector key %q: %v", resourceSelector.SelectorKeyRegex,
			key, err)
	}
	if !doesMatch {
		return false
	}

	doesMatch, err = regexp.MatchString(resourceSelector.SelectorValueRegex, value)
	if err != nil {
		klog.Errorf("error evaluating regex pattern %q for selector value %q: %v", resourceSelector.SelectorValueRegex,
			value, err)
	}
	return doesMatch
}

func doesMatchImageResource(regex string, imageReference string) bool {
	klog.Infof("testing imageReference %q using regex pattern %q", imageReference, regex)

	doesMatch, err := regexp.MatchString(regex, imageReference)
	if err != nil {
		return false
	}

	if doesMatch {
		klog.Infof("image reference %q does match provided regex pattern %q", imageReference, regex)
		return true
	}

	klog.Infof("image reference %q does NOT match provided regex pattern %q", imageReference, regex)
	return false
}
