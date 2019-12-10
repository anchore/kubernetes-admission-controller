/*
 * Anchore Engine API Server
 *
 * This is the Anchore Engine API. Provides the primary external API for users of the service.
 *
 * API version: 0.1.12
 * Contact: nurmi@anchore.com
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client
// ContentJavaPackageResponseContent struct for ContentJavaPackageResponseContent
type ContentJavaPackageResponseContent struct {
	Package string `json:"package,omitempty"`
	ImplementationVersion string `json:"implementation-version,omitempty"`
	SpecificationVersion string `json:"specification-version,omitempty"`
	MavenVersion string `json:"maven-version,omitempty"`
	Location string `json:"location,omitempty"`
	Type string `json:"type,omitempty"`
	Origin string `json:"origin,omitempty"`
}
