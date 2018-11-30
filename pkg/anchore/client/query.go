package client


// An image record that contains packages
type ImageWithPackages struct {

	Image *ImageReference `json:"image,omitempty"`

	Packages []PackageReference `json:"packages,omitempty"`
}


// Pagination wrapped list of images that match some filter
type PaginatedImageList struct {

	// The page number returned (should match the requested page query string param)
	Page string `json:"page,omitempty"`

	// True if additional pages exist (page + 1) or False if this is the last page
	NextPage string `json:"next_page,omitempty"`

	// The number of items sent in this response
	ReturnedCount int32 `json:"returned_count,omitempty"`

	Images []ImageWithPackages `json:"images,omitempty"`
}

// A paginated listing of vulnerability records sorted by ID in descending order
type PaginatedVulnerabilityList struct {

	// The page number returned (should match the requested page query string param)
	Page string `json:"page,omitempty"`

	// True if additional pages exist (page + 1) or False if this is the last page
	NextPage string `json:"next_page,omitempty"`

	// The number of items sent in this response
	ReturnedCount int32 `json:"returned_count,omitempty"`

	// The listing of matching vulnerabilities for the query subject to pagination
	Vulnerabilities []StandaloneVulnerability `json:"vulnerabilities,omitempty"`
}

// Pagination wrapped list of images with vulnerabilties that match some filter
type PaginatedVulnerableImageList struct {

	// The page number returned (should match the requested page query string param)
	Page string `json:"page,omitempty"`

	// True if additional pages exist (page + 1) or False if this is the last page
	NextPage string `json:"next_page,omitempty"`

	// The number of items sent in this response
	ReturnedCount int32 `json:"returned_count,omitempty"`

	Images []VulnerableImage `json:"images,omitempty"`
}

// A record of an image vulnerable to some known vulnerability. Includes vulnerable package information
type VulnerableImage struct {

	Image *ImageReference `json:"image,omitempty"`

	AffectedPackages []VulnerablePackageReference `json:"affected_packages,omitempty"`
}

// List of Vulnerability objects
type VulnerabilityList []Vulnerability


type Vulnerability struct {

	// The vulnerability identifier, such as CVE-2017-100, or RHSA-2017123
	Vuln string `json:"vuln,omitempty"`

	// The package containing a fix, if available
	Fix string `json:"fix,omitempty"`

	// The severity of the vulnerability
	Severity string `json:"severity,omitempty"`

	// The package name and version that are vulnerable in the image
	Package_ string `json:"package,omitempty"`

	// The url for more information about the vulnerability
	Url string `json:"url,omitempty"`

	// The name of the feed where vulnerability match was made
	Feed string `json:"feed,omitempty"`

	// The name of the feed group where vulnerability match was made
	FeedGroup string `json:"feed_group,omitempty"`

	// The name of the vulnerable package artifact
	PackageName string `json:"package_name,omitempty"`

	// The version of the vulnerable package artifact
	PackageVersion string `json:"package_version,omitempty"`

	// The type of vulnerable package
	PackageType string `json:"package_type,omitempty"`

	// The CPE string (if applicable) describing the package to vulnerability match
	PackageCpe string `json:"package_cpe,omitempty"`

	// The location (if applicable) of the vulnerable package in the container filesystem
	PackagePath string `json:"package_path,omitempty"`
}


// A single vulnerability record in a single namespace, the unique key is the combinatino of the id and namespace
type StandaloneVulnerability struct {

	// Vulnerability identifier. May be CVE-X, RHSA-X, etc. Not necessarily unique across namespaces
	Id string `json:"id,omitempty"`

	// The namespace for the vulnerability record to avoid conflicts for the same id in different distros or sources (e.g. deb vs ubuntu for same CVE)
	Namespace string `json:"namespace,omitempty"`

	// The array of packages (typically packages) that are vulnerable-to or provide fixes-for this vulnerability
	AffectedPackages []PackageReference `json:"affected_packages,omitempty"`

	// Severity label specific to the namepsace
	Severity string `json:"severity,omitempty"`

	// URL for the upstream CVE record in the reporting source (e.g. ubuntu security tracker)
	Link string `json:"link,omitempty"`
}

// A record of a software item which is vulnerable or carries a fix for a vulnerability
type VulnerablePackageReference struct {

	// Package name
	Name string `json:"name,omitempty"`

	// A version for the package. If null, then references all versions
	Version string `json:"version,omitempty"`

	// Package type (e.g. package, rpm, deb, apk, jar, npm, gem, ...)
	Type_ string `json:"type,omitempty"`

	// Severity of vulnerability affecting package
	Severity string `json:"severity,omitempty"`

	// Vulnerability namespace of affected package
	Namespace string `json:"namespace,omitempty"`
}



