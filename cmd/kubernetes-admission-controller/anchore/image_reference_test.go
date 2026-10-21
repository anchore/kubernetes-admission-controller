package anchore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testDigest = "sha256:7f0933debc98a8c2a8ed56fca4bf3375e7a1bf314c0924247b15c6239e253a07"

func TestParseImageReference(t *testing.T) {
	testCases := []struct {
		reference string
		expected  imageReference
	}{
		{
			reference: "docker.io/library/alpine:3.20",
			expected:  imageReference{repository: "docker.io/library/alpine", tag: "docker.io/library/alpine:3.20"},
		},
		{
			reference: "alpine",
			expected:  imageReference{repository: "alpine", tag: "alpine"},
		},
		{
			reference: "registry.example.com:5000/team/app",
			expected:  imageReference{repository: "registry.example.com:5000/team/app", tag: "registry.example.com:5000/team/app"},
		},
		{
			reference: "registry.example.com/sourcegraph/precise-code-intel-worker:7.7.359@" + testDigest,
			expected: imageReference{
				repository: "registry.example.com/sourcegraph/precise-code-intel-worker",
				tag:        "registry.example.com/sourcegraph/precise-code-intel-worker:7.7.359",
				digest:     testDigest,
			},
		},
		{
			reference: "registry.example.com:5000/team/app@" + testDigest,
			expected: imageReference{
				repository: "registry.example.com:5000/team/app",
				tag:        "registry.example.com:5000/team/app:latest",
				digest:     testDigest,
			},
		},
		{
			reference: "registry.example.com:5000/team/app:1.0@" + testDigest,
			expected: imageReference{
				repository: "registry.example.com:5000/team/app",
				tag:        "registry.example.com:5000/team/app:1.0",
				digest:     testDigest,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.reference, func(t *testing.T) {
			assert.Equal(t, testCase.expected, parseImageReference(testCase.reference))
		})
	}
}

func TestImageReference_DigestPullString(t *testing.T) {
	ref := parseImageReference("registry.example.com/team/app:1.0@" + testDigest)

	assert.True(t, ref.isDigestPinned())
	assert.Equal(t, "registry.example.com/team/app@"+testDigest, ref.digestPullString())
}

func TestImageReference_MatchesDigest(t *testing.T) {
	ref := parseImageReference("app:1.0@" + testDigest)
	pinned := testDigest
	other := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	assert.True(t, ref.matchesDigest(&pinned, nil), "platform manifest digest")
	assert.True(t, ref.matchesDigest(&other, &pinned), "manifest list digest")
	assert.False(t, ref.matchesDigest(&other, &other))
	assert.False(t, ref.matchesDigest(nil, nil))
}
