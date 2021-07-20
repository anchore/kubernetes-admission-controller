package validation

type ResourceSelectorType string

const (
	GeneralResourceSelectorType   ResourceSelectorType = "resource"
	NamespaceResourceSelectorType ResourceSelectorType = "namespace"
	ImageResourceSelectorType     ResourceSelectorType = "image"
)
