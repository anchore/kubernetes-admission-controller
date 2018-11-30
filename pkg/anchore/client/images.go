package client

import (
	"time"
)

// A unique image in the engine. May have multiple tags or references. Unique to an image content across registries or repositories.
type AnchoreImage struct {

	ImageContent *ImageContent `json:"image_content,omitempty"`

	// Details specific to an image reference and type such as tag and image source
	ImageDetail []ImageDetail `json:"image_detail,omitempty"`

	LastUpdated time.Time `json:"last_updated,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`

	ImageDigest string `json:"imageDigest,omitempty"`

	UserId string `json:"userId,omitempty"`

	// State of the image
	ImageStatus string `json:"image_status,omitempty"`

	// A state value for the current status of the analysis progress of the image
	AnalysisStatus string `json:"analysis_status,omitempty"`
}

// A list of Anchore Images
type AnchoreImageList []AnchoreImage

// A unique image in the engine.
type AnchoreImageTagSummary struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	ImageId string `json:"imageId,omitempty"`

	AnalysisStatus string `json:"analysis_status,omitempty"`

	Fulltag string `json:"fulltag,omitempty"`

	CreatedAt int32 `json:"created_at,omitempty"`

	AnalyzedAt int32 `json:"analyzed_at,omitempty"`

	TagDetectedAt int32 `json:"tag_detected_at,omitempty"`
}

// a list of AnchoreImageTagSummary objects
type AnchoreImageTagSummaryList []AnchoreImageTagSummary

// File content listings from images
type ContentFilesResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Content []ContentFilesResponseContent `json:"content,omitempty"`
}

type ContentFilesResponseContent struct {

	Filename string `json:"filename,omitempty"`

	Gid int32 `json:"gid,omitempty"`

	Linkdest string `json:"linkdest,omitempty"`

	Mode string `json:"mode,omitempty"`

	Sha256 string `json:"sha256,omitempty"`

	Size int32 `json:"size,omitempty"`

	Type_ string `json:"type,omitempty"`

	Uid int32 `json:"uid,omitempty"`
}

// Java package content listings from images
type ContentJavaPackageResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Content []ContentJavaPackageResponseContent `json:"content,omitempty"`
}


type ContentJavaPackageResponseContent struct {

	Package_ string `json:"package,omitempty"`

	ImplementationVersion string `json:"implementation-version,omitempty"`

	SpecificationVersion string `json:"specification-version,omitempty"`

	MavenVersion string `json:"maven-version,omitempty"`

	Location string `json:"location,omitempty"`

	Type_ string `json:"type,omitempty"`

	Origin string `json:"origin,omitempty"`
}


// Package content listings from images
type ContentPackageResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Content []ContentPackageResponseContent `json:"content,omitempty"`
}


type ContentPackageResponseContent struct {

	Package_ string `json:"package,omitempty"`

	Version string `json:"version,omitempty"`

	Size string `json:"size,omitempty"`

	Type_ string `json:"type,omitempty"`

	Origin string `json:"origin,omitempty"`

	License string `json:"license,omitempty"`

	Location string `json:"location,omitempty"`
}

// A metadata content record for a specific image, containing different content type entries
type ImageContent struct {
}

// A summary of an image identity, including digest, id (if available), and any tags known to have ever been mapped to the digest
type ImageReference struct {

	// The image digest
	Digest string `json:"digest,omitempty"`

	// The image id if available
	Id string `json:"id,omitempty"`

	// Timestamp, in rfc3339 format, indicating when the image state became 'analyzed' in Anchore Engine.
	AnalyzedAt string `json:"analyzed_at,omitempty"`

	TagHistory []TagEntry `json:"tag_history,omitempty"`
}

// Analysis report json to be imported
type ImageAnalysisReport struct {
}

// A request to add an image to be watched and analyzed by the engine. Optionally include the dockerfile content. Either digest or tag must be present
type ImageAnalysisRequest struct {

	// Content of the dockerfile for the image, if available
	Dockerfile string `json:"dockerfile,omitempty"`

	// A full pullable digest reference for an image. e.g. docker.io/nginx@sha256:abc123
	Digest string `json:"digest,omitempty"`

	// Full pullable tag reference for image. e.g. docker.io/nginx:latest
	Tag string `json:"tag"`

	// Optional override of the image creation time, only honored when both tag and digest are also supplied  e.g. 2018-10-17T18:14:00Z
	CreatedAt time.Time `json:"created_at,omitempty"`

	// The type of image this is adding, defaults to \"docker\"
	ImageType string `json:"image_type,omitempty"`

	// Annotations to be associated with the added image in key/value form
	Annotations *interface{} `json:"annotations,omitempty"`
}

// A metadata detail record for a specific image. Multiple detail records may map a single catalog image.
type ImageDetail struct {

	CreatedAt time.Time `json:"created_at,omitempty"`

	LastUpdated time.Time `json:"last_updated,omitempty"`

	// Full docker-pullalbe tag string referencing the image
	Fulltag string `json:"fulltag,omitempty"`

	// Full docker-pullable digest string including the registry url and repository necessary get the image
	Fulldigest string `json:"fulldigest,omitempty"`

	UserId string `json:"userId,omitempty"`

	ImageId string `json:"imageId,omitempty"`

	Registry string `json:"registry,omitempty"`

	Repo string `json:"repo,omitempty"`

	Dockerfile string `json:"dockerfile,omitempty"`

	// The parent Anchore Image record to which this detail maps
	ImageDigest string `json:"imageDigest,omitempty"`
}

// Filter for an image list by id, tag, or digest, but not both
type ImageFilter struct {

	Tag string `json:"tag,omitempty"`

	Digest string `json:"digest,omitempty"`
}

// A reference to an image
type ImageRef struct {

	Type_ string `json:"type"`

	Value string `json:"value"`
}

// Generic wrapper for content listings from images
type ContentResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Content []interface{} `json:"content,omitempty"`
}

// Generic wrapper for metadata listings from images
type MetadataResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	MetadataType string `json:"metadata_type,omitempty"`
}

// envelope containing list of vulnerabilities
type VulnerabilityResponse struct {

	ImageDigest string `json:"imageDigest,omitempty"`

	VulnerabilityType string `json:"vulnerability_type,omitempty"`

	Vulnerabilities *VulnerabilityList `json:"vulnerabilities,omitempty"`
}
