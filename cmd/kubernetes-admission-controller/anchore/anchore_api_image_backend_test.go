package anchore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	anchoreEnterprise "github.com/anchore/enterprise-client-go/pkg/enterprise"
	"github.com/stretchr/testify/assert"
)

// newTestAPIImageBackend returns an APIImageBackend whose requests go to handler instead of an Anchore deployment.
func newTestAPIImageBackend(t *testing.T, handler http.HandlerFunc) APIImageBackend {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cfg := anchoreEnterprise.NewConfiguration()
	cfg.Servers = anchoreEnterprise.ServerConfigurations{{URL: server.URL}}

	return APIImageBackend{client: anchoreEnterprise.NewAPIClient(cfg).ImagesApi}
}

func TestAPIImageBackend_Analyze(t *testing.T) {
	testCases := []struct {
		name           string
		imageReference string
		expectedSource map[string]interface{}
	}{
		{
			name:           "tag reference uses a tag source",
			imageReference: "registry.example.com/team/app:1.0",
			expectedSource: map[string]interface{}{
				"tag": map[string]interface{}{"pull_string": "registry.example.com/team/app:1.0"},
			},
		},
		{
			name:           "digest-pinned reference uses a digest source",
			imageReference: "registry.example.com/team/app:1.0@" + testDigest,
			expectedSource: map[string]interface{}{
				"digest": map[string]interface{}{
					"pull_string": "registry.example.com/team/app@" + testDigest,
					"tag":         "registry.example.com/team/app:1.0",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var requestBody map[string]interface{}
			backend := newTestAPIImageBackend(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &requestBody)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"image_digest": %q}`, testDigest)
			})

			err := backend.Analyze(Credential{}, testCase.imageReference)

			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedSource, requestBody["source"])
		})
	}
}

func TestAPIImageBackend_Get(t *testing.T) {
	const otherDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	imageList := fmt.Sprintf(`{"items": [
		{"image_digest": %q, "analysis_status": "analyzed", "created_at": "2026-01-01T00:00:00Z"},
		{"image_digest": %q, "analysis_status": "analyzed", "created_at": "2026-02-01T00:00:00Z"}
	]}`, otherDigest, testDigest)

	testCases := []struct {
		name             string
		imageReference   string
		expectedFullTag  string
		expectedHistory  string
		expectedDigest   string
		expectedNotFound bool
	}{
		{
			name:            "tag reference",
			imageReference:  "registry.example.com/team/app:1.0",
			expectedFullTag: "registry.example.com/team/app:1.0",
			expectedDigest:  otherDigest,
		},
		{
			name:            "digest-pinned reference returns the pinned image",
			imageReference:  "registry.example.com/team/app:1.0@" + testDigest,
			expectedFullTag: "registry.example.com/team/app:1.0",
			expectedHistory: "true",
			expectedDigest:  testDigest,
		},
		{
			name:             "digest-pinned reference with no matching image is not found",
			imageReference:   "registry.example.com/team/app:1.0@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			expectedFullTag:  "registry.example.com/team/app:1.0",
			expectedHistory:  "true",
			expectedNotFound: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var fullTag, history string
			backend := newTestAPIImageBackend(t, func(w http.ResponseWriter, r *http.Request) {
				fullTag = r.URL.Query().Get("full_tag")
				history = r.URL.Query().Get("history")
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, imageList)
			})

			image, err := backend.Get(Credential{}, testCase.imageReference)

			assert.Equal(t, testCase.expectedFullTag, fullTag)
			assert.Equal(t, testCase.expectedHistory, history)
			if testCase.expectedNotFound {
				assert.True(t, errors.Is(err, ErrImageDoesNotExist), "expected ErrImageDoesNotExist, got %v", err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedDigest, image.Digest)
		})
	}
}
