package admission

import (
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type ResourceSelector struct {
	Type               ResourceSelectorType // The resource to do selection on, supported: pod, namespace
	SelectorKeyRegex   string               // The regex to select a matching key
	SelectorValueRegex string               // The regex to apply to the label/annotation of the specified resource type
}

func doesObjectMatchResourceSelector(object *metav1.ObjectMeta, resourceSelector ResourceSelector) bool {
	mapArray := []map[string]string{object.Labels, object.Annotations}
	for _, kvMap := range mapArray {
		for k, v := range kvMap {
			if doesKeyValuePairMatchResourceSelector(k, v, resourceSelector) {
				return true
			}
		}
	}

	// Treat Name specially
	if strings.ToLower(resourceSelector.SelectorKeyRegex) == "name" {
		doesSelectorMatchName, err := regexp.MatchString(resourceSelector.SelectorValueRegex, object.Name)
		if err != nil {
			klog.Error("Failed evaluating regex against metadata Name entry = ", object.Name, " regex = ", resourceSelector.SelectorValueRegex, " err=", err)
		}
		return doesSelectorMatchName
	}

	return false
}

func doesKeyValuePairMatchResourceSelector(key, value string, resourceSelector ResourceSelector) bool {
	doesMatch, err := regexp.MatchString(resourceSelector.SelectorKeyRegex, key)
	if err != nil {
		klog.Error("Error evaluating regexp key= ", key, " regex = ", resourceSelector.SelectorKeyRegex, " err=", err)
	}
	if !doesMatch {
		return false
	}

	doesMatch, err = regexp.MatchString(resourceSelector.SelectorValueRegex, value)
	if err != nil {
		klog.Error("Error evaluating regexp ", " value = ", value, " regex = ", resourceSelector.SelectorValueRegex,
			" err=", err)
	}
	return doesMatch
}

func doesMatchImageResource(regex string, imageReference string) bool {
	doesMatch, err := regexp.MatchString(regex, imageReference)
	if err != nil {
		return false
	}

	return doesMatch
}
