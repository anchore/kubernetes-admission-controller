package admission

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDoesObjectMatchResourceSelector(t *testing.T) {
	testCases := []struct {
		name      string
		selector  ResourceSelector
		assertion func(t *testing.T, actual bool)
	}{
		{
			name:      "should match anything",
			selector:  ResourceSelector{GeneralResourceSelectorType, ".*", ".*"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'label.*'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "label.*", ".*"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should NOT match key '^label$'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "^label$", ".*"},
			assertion: assertShouldNotMatch,
		},
		{
			name:      "should match key 'label'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "label", ".*"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'labelowner'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "labelowner", ".*"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'labelowner' with value 'lsometeam'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "labelowner", "lsometeam"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'labelowner' with value 'lsome'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "labelowner", "lsome"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'annotation.*'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "annotation.*", ".*"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'annotationowner' with value 'asometeam'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "annotationowner", "asometeam"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should match key 'own' with value '.*team'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "own", ".*team"},
			assertion: assertShouldMatch,
		},
		{
			name:      "should NOT match key 'notfound'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "notfound", ".*"},
			assertion: assertShouldNotMatch,
		},
		{
			name:      "should NOT match value 'anotherteam'",
			selector:  ResourceSelector{GeneralResourceSelectorType, ".*", "anotherteam"},
			assertion: assertShouldNotMatch,
		},
		{
			name:      "should NOT match key 'owner' with value 'anotherteam'",
			selector:  ResourceSelector{GeneralResourceSelectorType, "owner", "anotherteam"},
			assertion: assertShouldNotMatch,
		},
	}

	metadata := testMetadata()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := doesObjectMatchResourceSelector(&metadata, testCase.selector)
			testCase.assertion(t, actual)
		})
	}
}

func TestDoesMatchImageResource(t *testing.T) {
	testCases := []struct {
		name               string
		selectorValueRegex string
		image              string
		assertion          func(t *testing.T, found bool)
	}{
		{
			name:               "match any image",
			selectorValueRegex: ".*",
			image:              "alpine",
			assertion:          assertShouldMatch,
		},
		{
			name:               "match image with same tag",
			selectorValueRegex: ".*:latest",
			image:              "alpine:latest",
			assertion:          assertShouldMatch,
		},
		{
			name:               "don't match image with different tag",
			selectorValueRegex: ".*:latest",
			image:              "debian:jessie",
			assertion:          assertShouldNotMatch,
		},
		{
			name:               "match image by exact name",
			selectorValueRegex: "alpine",
			image:              "alpine",
			assertion:          assertShouldMatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := doesMatchImageResource(testCase.selectorValueRegex, testCase.image)
			testCase.assertion(t, actual)
		})
	}
}

func testMetadata() metav1.ObjectMeta {
	labels := map[string]string{
		"labelkey":   "lvalue",
		"labelkey2":  "lvalue2",
		"labelowner": "lsometeam",
	}

	annotations := map[string]string{
		"annotationkey":   "avalue",
		"annotationkey2":  "avalue2",
		"annotationowner": "asometeam",
	}

	return metav1.ObjectMeta{Labels: labels, Annotations: annotations}
}

func assertShouldMatch(t *testing.T, doesMatch bool) {
	t.Helper()

	if !doesMatch {
		t.Error("Failed to match")
	}
}

func assertShouldNotMatch(t *testing.T, doesMatch bool) {
	t.Helper()

	if doesMatch {
		t.Error("Incorrectly matched")
	}
}
