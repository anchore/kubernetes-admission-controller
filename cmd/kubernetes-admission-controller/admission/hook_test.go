package admission

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/validation"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHook_Validate(t *testing.T) {
	testCases := []struct {
		name                      string
		requestedKubernetesObject interface{}
		gateMode                  validation.Mode
		expectedAllowedResponse   bool
	}{
		{
			name:                      "policy gating, image exists, image passes",
			requestedKubernetesObject: mockPod(passingImageName),
			gateMode:                  validation.PolicyGateMode,
			expectedAllowedResponse:   true,
		},
		{
			name:                      "policy gating, image exists, image fails",
			requestedKubernetesObject: mockPod(failingImageName),
			gateMode:                  validation.PolicyGateMode,
			expectedAllowedResponse:   false,
		},
		{
			name:                      "policy gating, image doesn't exist",
			requestedKubernetesObject: mockPod(nonexistentImageName),
			gateMode:                  validation.PolicyGateMode,
			expectedAllowedResponse:   false,
		},
		{
			name:                      "analysis gating, image exists, image passes",
			requestedKubernetesObject: mockPod(passingImageName),
			gateMode:                  validation.AnalysisGateMode,
			expectedAllowedResponse:   true,
		},
		{
			name:                      "analysis gating, image doesn't exist",
			requestedKubernetesObject: mockPod(nonexistentImageName),
			gateMode:                  validation.AnalysisGateMode,
			expectedAllowedResponse:   false,
		},
		{
			name:                      "analysis gating, image doesn't exist",
			requestedKubernetesObject: mockPod(nonexistentImageName),
			gateMode:                  validation.AnalysisGateMode,
			expectedAllowedResponse:   false,
		},
		{
			name:                      "passive gating, image exists, image passes",
			requestedKubernetesObject: mockPod(passingImageName),
			gateMode:                  validation.BreakGlassMode,
			expectedAllowedResponse:   true,
		},
		{
			name:                      "passive gating, image doesn't exist",
			requestedKubernetesObject: mockPod(nonexistentImageName),
			gateMode:                  validation.BreakGlassMode,
			expectedAllowedResponse:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// arrange
			anchoreService := mockAnchoreService()
			defer anchoreService.Close()

			hook := Hook{
				Config:      mockControllerConfiguration(testCase.gateMode, anchoreService),
				Clientset:   kubernetes.Clientset{},
				AnchoreAuth: mockAnchoreAuthConfig(),
			}
			admissionRequest := mockAdmissionRequest(t, testCase.requestedKubernetesObject)

			// act
			admissionResponse := hook.Validate(&admissionRequest)
			t.Logf("admission response: %s\n", admissionResponse)

			// assert
			assert.Equal(t, testCase.expectedAllowedResponse, admissionResponse.Allowed)
		})
	}
}

func mockPod(image string) v1.Pod {
	return v1.Pod{
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "Container1",
					Image:   image,
					Command: []string{"bin/bash", "bin"},
				},
			},
		},
	}
}

func mockControllerConfiguration(mode validation.Mode, testServer *httptest.Server) ControllerConfiguration {
	return ControllerConfiguration{
		Validator:       ValidatorConfiguration{Enabled: true, RequestAnalysis: true},
		AnchoreEndpoint: testServer.URL,
		PolicySelectors: []PolicySelector{
			{
				ResourceSelector: ResourceSelector{Type: ImageResourceSelectorType, SelectorKeyRegex: ".*", SelectorValueRegex: ".*"},
				Mode:             mode,
				PolicyReference:  anchore.ClientConfiguration{Username: "admin"},
			},
		},
	}
}

func mockAnchoreAuthConfig() anchore.AuthConfiguration {
	return anchore.AuthConfiguration{
		Users: []anchore.Credential{
			{"admin", "password"},
		},
	}
}

func mockAdmissionRequest(t *testing.T, requestedObject interface{}) v1beta1.AdmissionRequest {
	t.Helper()

	marshalledObject, err := json.Marshal(requestedObject)
	if err != nil {
		t.Fatal(err)
	}

	return v1beta1.AdmissionRequest{
		UID: "abc123",
		Kind: metav1.GroupVersionKind{Group: v1.GroupName, Version: v1.SchemeGroupVersion.Version,
			Kind: "Pod"},
		Resource:    metav1.GroupVersionResource{Group: metav1.GroupName, Version: "v1", Resource: "pods"},
		SubResource: "someresource",
		Name:        "somename",
		Namespace:   "default",
		Operation:   "CREATE",
		Object:      runtime.RawExtension{Raw: marshalledObject},
	}
}

func mockAnchoreService() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/images" {
			switch r.URL.Query().Get("fulltag") {
			case passingImageName:
				fmt.Fprintln(w, mockImageLookupResponse(passingImageName, passingImageDigest))
				return
			case failingImageName:
				fmt.Fprintln(w, mockImageLookupResponse(failingImageName, failingImageDigest))
				return
			}

			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, imageLookupError)
			return
		}

		switch r.URL.Path {
		case urlForImageCheck(passingImageDigest):
			fmt.Fprintln(w, mockImageCheckResponse(passingImageName, passingImageDigest, passingStatus))
			return
		case urlForImageCheck(failingImageDigest):
			fmt.Fprintln(w, mockImageCheckResponse(failingImageName, failingImageDigest, failingStatus))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, imageNotFound)
	}))
}

const (
	passingImageName     = "alpine"
	failingImageName     = "bad-alpine"
	nonexistentImageName = "ubuntu"
	passingImageDigest   = "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b"
	failingImageDigest   = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	passingStatus        = "pass"
	failingStatus        = "fail"
)

const imageNotFound = `
{
  "message": "could not get image record from anchore"
}
`

const imageLookupError = `{"detail": {}, "httpcode": 404, "message": "image data not found in DB" }`

func urlForImageCheck(imageDigest string) string {
	return fmt.Sprintf("/images/%s/check", imageDigest)
}

func mockImageCheckResponse(imageName, imageDigest, status string) string {
	return fmt.Sprintf(`
[
  {
    "%s": {
      "docker.io/%s:latest": [
        {
          "detail": {},
          "last_evaluation": "2018-12-03T17:46:13Z",
          "policyId": "2c53a13c-1765-11e8-82ef-23527761d060",
          "status": "%s"
        }
      ]
    }
  }
]
`, imageDigest, imageName, status)
}

func mockImageLookupResponse(imageName, imageDigest string) string {
	return fmt.Sprintf(`
[
  {
    "analysis_status": "analyzed",
    "analyzed_at": "2018-12-03T18:24:54Z",
    "annotations": {},
    "created_at": "2018-12-03T18:24:43Z",
    "imageDigest": "%s",
    "image_content": {
      "metadata": {
        "arch": "amd64",
        "distro": "alpine",
        "distro_version": "3.8.1",
        "dockerfile_mode": "Guessed",
        "image_size": 2206931,
        "layer_count": 1
      }
    },
    "image_detail": [
      {
        "created_at": "2018-12-03T18:24:43Z",
        "digest": "%s",
        "dockerfile": "RlJPTSBzY3JhdGNoCkFERCBmaWxlOjI1YzEwYjFkMWI0MWQ0NmExODI3YWQwYjBkMjM4OWMyNGRmNmQzMTQzMDAwNWZmNGU5YTJkODRlYTIzZWJkNDIgaW4gLyAKQ01EIFsiL2Jpbi9zaCJdCg==",
        "fulldigest": "docker.io/%s@%s",
        "fulltag": "docker.io/%s:latest",
        "imageDigest": "%s",
        "imageId": "196d12cf6ab19273823e700516e98eb1910b03b17840f9d5509f03858484d321",
        "last_updated": "2018-12-03T18:24:54Z",
        "registry": "docker.io",
        "repo": "%s",
        "tag": "latest",
        "tag_detected_at": "2018-12-03T18:24:43Z",
        "userId": "admin"
      }
    ],
    "image_status": "active",
    "image_type": "docker",
    "last_updated": "2018-12-03T18:24:54Z",
    "parentDigest": "sha256:621c2f39f8133acb8e64023a94dbdf0d5ca81896102b9e57c0dc184cadaf5528",
    "userId": "admin"
  }
]
`, imageDigest, imageDigest, imageName, imageDigest, imageName, imageDigest, imageName)
}
