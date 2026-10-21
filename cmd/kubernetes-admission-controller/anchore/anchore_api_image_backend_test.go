package anchore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	anchoreEngine "github.com/anchore/enterprise-client-go-v1/pkg/engine"
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

// newTestAPIImageBackendV1 returns an APIImageBackendV1 whose requests go to handler instead of an Anchore deployment.
func newTestAPIImageBackendV1(t *testing.T, handler http.HandlerFunc) APIImageBackendV1 {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cfg := anchoreEngine.NewConfiguration()
	cfg.Servers = anchoreEngine.ServerConfigurations{{URL: server.URL}}

	return APIImageBackendV1{client: anchoreEngine.NewAPIClient(cfg).ImagesApi}
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

// imagesAPIFormat holds the JSON shapes that differ between the Enterprise (v2) and v1 image APIs.
type imagesAPIFormat struct {
	// record renders one image record.
	record func(imageDigest, parentDigest, createdAt string) string
	// single wraps a record as a response from GET /images/{digest}.
	single func(record string) string
	// list wraps records as a response from GET /images.
	list func(records ...string) string
	// fullTagParam is the name of the query parameter that filters GET /images by tag.
	fullTagParam string
}

var (
	enterpriseImagesAPIFormat = imagesAPIFormat{
		record: func(imageDigest, parentDigest, createdAt string) string {
			return fmt.Sprintf(`{"image_digest": %q, "parent_digest": %q, "analysis_status": "analyzed", "created_at": %q}`,
				imageDigest, parentDigest, createdAt)
		},
		single: func(record string) string { return record },
		list: func(records ...string) string {
			return `{"items": [` + strings.Join(records, ",") + `]}`
		},
		fullTagParam: "full_tag",
	}
	v1ImagesAPIFormat = imagesAPIFormat{
		record: func(imageDigest, parentDigest, createdAt string) string {
			return fmt.Sprintf(`{"imageDigest": %q, "parentDigest": %q, "analysis_status": "analyzed", "created_at": %q}`,
				imageDigest, parentDigest, createdAt)
		},
		single: func(record string) string { return "[" + record + "]" },
		list: func(records ...string) string {
			return "[" + strings.Join(records, ",") + "]"
		},
		fullTagParam: "fulltag",
	}
)

// fakeImagesAPI serves the two endpoints the backends read images from and records what was asked of them.
type fakeImagesAPI struct {
	// byDigest maps a digest to the GET /images/{digest} response body; other digests get a 404.
	byDigest map[string]string
	// digestStatus, when set, is returned by GET /images/{digest} instead of a body.
	digestStatus int
	// list is the GET /images response body.
	list string

	digestRequested string
	// listQuery is nil when GET /images was not called.
	listQuery url.Values
}

func (f *fakeImagesAPI) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if digest := strings.TrimPrefix(r.URL.Path, "/images/"); digest != r.URL.Path {
		f.digestRequested = digest
		body, ok := f.byDigest[digest]
		switch {
		case f.digestStatus != 0:
			w.WriteHeader(f.digestStatus)
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = io.WriteString(w, body)
		}
		return
	}

	f.listQuery = r.URL.Query()
	_, _ = io.WriteString(w, f.list)
}

func TestAPIImageBackends_Get(t *testing.T) {
	const (
		otherDigest    = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		platformDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		missingDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)

	backends := []struct {
		name       string
		format     imagesAPIFormat
		newBackend func(t *testing.T, handler http.HandlerFunc) ImageBackend
	}{
		{
			name:   "enterprise",
			format: enterpriseImagesAPIFormat,
			newBackend: func(t *testing.T, handler http.HandlerFunc) ImageBackend {
				return newTestAPIImageBackend(t, handler)
			},
		},
		{
			name:   "v1",
			format: v1ImagesAPIFormat,
			newBackend: func(t *testing.T, handler http.HandlerFunc) ImageBackend {
				return newTestAPIImageBackendV1(t, handler)
			},
		},
	}

	for _, backend := range backends {
		format := backend.format
		testCases := []struct {
			name           string
			imageReference string
			api            fakeImagesAPI
			// expectedFullTag and expectedHistory are the GET /images query; nil expectedFullTag means
			// GET /images is not called.
			expectedFullTag  *string
			expectedHistory  string
			expectedDigest   string
			expectedNotFound bool
			expectedError    bool
		}{
			{
				name:           "tag reference uses the tag's images",
				imageReference: "registry.example.com/team/app:1.0",
				api: fakeImagesAPI{list: format.list(
					format.record(otherDigest, "", "2026-01-01T00:00:00Z"),
					format.record(testDigest, "", "2026-02-01T00:00:00Z"),
				)},
				expectedFullTag: stringPtr("registry.example.com/team/app:1.0"),
				expectedDigest:  otherDigest,
			},
			{
				name:           "pinned digest analyzed only under another tag is found by digest",
				imageReference: "registry.example.com/team/app@" + testDigest,
				api: fakeImagesAPI{
					byDigest: map[string]string{testDigest: format.single(format.record(testDigest, "", "2026-01-01T00:00:00Z"))},
					list:     format.list(),
				},
				expectedDigest: testDigest,
			},
			{
				name:           "pinned manifest list digest is found as the parent digest of the tag's images",
				imageReference: "registry.example.com/team/app:1.0@" + testDigest,
				api: fakeImagesAPI{list: format.list(
					format.record(otherDigest, "", "2026-01-01T00:00:00Z"),
					format.record(platformDigest, testDigest, "2026-02-01T00:00:00Z"),
				)},
				expectedFullTag: stringPtr("registry.example.com/team/app:1.0"),
				expectedHistory: "true",
				expectedDigest:  platformDigest,
			},
			{
				name:           "pinned digest that Anchore does not have is not found",
				imageReference: "registry.example.com/team/app:1.0@" + missingDigest,
				api: fakeImagesAPI{list: format.list(
					format.record(otherDigest, "", "2026-01-01T00:00:00Z"),
				)},
				expectedFullTag:  stringPtr("registry.example.com/team/app:1.0"),
				expectedHistory:  "true",
				expectedNotFound: true,
			},
			{
				name:           "error looking up a pinned digest is returned",
				imageReference: "registry.example.com/team/app:1.0@" + testDigest,
				api:            fakeImagesAPI{digestStatus: http.StatusInternalServerError},
				expectedError:  true,
			},
		}

		for _, testCase := range testCases {
			t.Run(backend.name+"/"+testCase.name, func(t *testing.T) {
				api := testCase.api
				imageBackend := backend.newBackend(t, api.handler)

				image, err := imageBackend.Get(Credential{}, testCase.imageReference)

				if parsed := parseImageReference(testCase.imageReference); parsed.isDigestPinned() {
					assert.Equal(t, parsed.digest, api.digestRequested)
				} else {
					assert.Empty(t, api.digestRequested, "a tag reference must not be looked up by digest")
				}
				if testCase.expectedFullTag == nil {
					assert.Nil(t, api.listQuery, "expected GET /images not to be called")
				} else if assert.NotNil(t, api.listQuery, "expected GET /images to be called") {
					assert.Equal(t, *testCase.expectedFullTag, api.listQuery.Get(format.fullTagParam))
					assert.Equal(t, testCase.expectedHistory, api.listQuery.Get("history"))
				}

				switch {
				case testCase.expectedError:
					assert.Error(t, err)
					assert.False(t, errors.Is(err, ErrImageDoesNotExist), "a failed lookup must not be reported as not analyzed")
				case testCase.expectedNotFound:
					assert.True(t, errors.Is(err, ErrImageDoesNotExist), "expected ErrImageDoesNotExist, got %v", err)
				default:
					assert.NoError(t, err)
					assert.Equal(t, testCase.expectedDigest, image.Digest)
				}
			})
		}
	}
}

func stringPtr(s string) *string {
	return &s
}
