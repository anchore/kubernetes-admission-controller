package admission

import (
	"testing"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	testGenericObjectMeta = metav1.ObjectMeta{
		Name:        "generic-object",
		Labels:      map[string]string{"some-label-key": "some-label-value"},
		Annotations: map[string]string{"some-annotation-key": "some-annotation-value"},
	}
	testAnchorePolicyReference = anchore.PolicyReference{
		Username:       "test-user",
		PolicyBundleId: "test-policy-bundle-id",
	}
	testValidationMode = validation.PolicyGateMode
)

func TestDetermineGateConfiguration(t *testing.T) {
	testCases := []struct {
		name            string
		meta            metav1.ObjectMeta
		imageReference  string
		policySelectors []PolicySelector
		clientset       kubernetes.Clientset
		expected        *gateConfiguration
	}{
		{
			name:            "no policy selectors",
			policySelectors: nil,
			expected:        nil,
		},
		{
			name: "object meta matches resource selector",
			meta: testGenericObjectMeta,
			policySelectors: []PolicySelector{
				{
					ResourceSelector: ResourceSelector{
						Type:               GeneralResourceSelectorType,
						SelectorKeyRegex:   ".*",
						SelectorValueRegex: ".*",
					},
					Mode:            testValidationMode,
					PolicyReference: testAnchorePolicyReference,
				},
			},
			expected: &gateConfiguration{
				mode:            testValidationMode,
				policyReference: testAnchorePolicyReference,
			},
		},
		{
			name: "no object meta and matches image resource",
			meta: testGenericObjectMeta,
			policySelectors: []PolicySelector{
				{
					ResourceSelector: ResourceSelector{
						Type:               ImageResourceSelectorType,
						SelectorKeyRegex:   ".*",
						SelectorValueRegex: ".*",
					},
					Mode:            testValidationMode,
					PolicyReference: testAnchorePolicyReference,
				},
			},
			expected: &gateConfiguration{
				mode:            testValidationMode,
				policyReference: testAnchorePolicyReference,
			},
		},
		{
			name: "only unusable policy selectors, so no config returned",
			meta: testGenericObjectMeta,
			policySelectors: []PolicySelector{
				{
					ResourceSelector: ResourceSelector{
						Type:               ImageResourceSelectorType,
						SelectorKeyRegex:   "this-will-not-match",
						SelectorValueRegex: "this-will-not-match",
					},
					Mode:            testValidationMode,
					PolicyReference: testAnchorePolicyReference,
				},
			},
			expected: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := determineGateConfiguration(
				testCase.meta,
				testCase.imageReference,
				testCase.policySelectors,
				testCase.clientset,
			)

			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestSelectObjectMetaForMatching(t *testing.T) {
	// TODO: add tests for Kubernetes namespace lookups
	testCases := []struct {
		name                 string
		resourceSelectorType ResourceSelectorType
		meta                 metav1.ObjectMeta
		expected             *metav1.ObjectMeta
	}{
		{
			name:                 "general resource selector returns the object itself",
			resourceSelectorType: GeneralResourceSelectorType,
			meta:                 testGenericObjectMeta,
			expected:             &testGenericObjectMeta,
		},
		{
			name:                 "image resource selector returns nil",
			resourceSelectorType: ImageResourceSelectorType,
			meta:                 testGenericObjectMeta,
			expected:             nil,
		},
		{
			name:                 "unexpected resource selector returns nil",
			resourceSelectorType: "NonexistentResourceSelectorType",
			meta:                 testGenericObjectMeta,
			expected:             nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := selectObjectMetaForMatching(testCase.resourceSelectorType, testCase.meta, kubernetes.Clientset{})

			assert.Equal(t, testCase.expected, actual)
		})
	}
}
