package anchore

import "strings"

// imageReference is a container image reference from a pod spec, split into the parts the Anchore API needs.
// Anchore's tag source only accepts a tag-based pull string, so a reference pinned by digest
// (e.g. "registry/repo:1.0@sha256:abc") has to be sent as a digest source instead.
type imageReference struct {
	// repository is the reference without its tag or digest, e.g. "registry/repo".
	repository string
	// tag is the tag-based reference, e.g. "registry/repo:1.0". A digest source requires a tag, so when a
	// digest-pinned reference has no tag, "latest" is assumed. A reference that is not pinned by digest is
	// kept exactly as written.
	tag string
	// digest is the pinned digest, e.g. "sha256:abc". It is empty when the reference is not pinned by digest.
	digest string
}

func parseImageReference(reference string) imageReference {
	name, digest, _ := strings.Cut(reference, "@")

	repository := name
	// A colon after the last slash separates the tag; a colon before it belongs to a registry port.
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		repository = name[:i]
	} else if digest != "" {
		name += ":latest"
	}

	return imageReference{
		repository: repository,
		tag:        name,
		digest:     digest,
	}
}

func (r imageReference) isDigestPinned() bool {
	return r.digest != ""
}

// digestPullString returns the digest-based pull string, e.g. "registry/repo@sha256:abc".
func (r imageReference) digestPullString() string {
	return r.repository + "@" + r.digest
}

// matchesDigest reports whether an Anchore image record with the given digests is the image this reference
// is pinned to. A pod can pin either the platform-specific manifest digest (Anchore's image digest) or the
// multi-platform manifest list digest (Anchore's parent digest).
func (r imageReference) matchesDigest(imageDigest, parentDigest *string) bool {
	return (imageDigest != nil && *imageDigest == r.digest) || (parentDigest != nil && *parentDigest == r.digest)
}
