package admission

import (
	"encoding/json"
	"fmt"
	batchV1 "k8s.io/api/batch/v1"
	batchV1beta "k8s.io/api/batch/v1beta1"
	"net/http"
	"net/http/httptest"
	"testing"

	appsV1 "k8s.io/api/apps/v1"

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
		name                  string
		validationMode        validation.Mode
		admissionRequest      v1beta1.AdmissionRequest
		isExpectedToBeAllowed bool
	}{
		{
			name:                  "policy mode: image exists, image passes",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "policy mode: image exists, image fails",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, failingImageName),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: multiple images that all pass",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName, passingImageName, passingImageName),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "policy mode: first image passes, second image fails",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName, failingImageName),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: first image fails, second image passes",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, failingImageName, passingImageName),
			isExpectedToBeAllowed: false,
		},

		{
			name:                  "policy mode: image doesn't exist",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      podAdmissionRequest(t, nonexistentImageName),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "analysis mode: image has been analyzed",
			validationMode:        validation.AnalysisGateMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "analysis mode: image doesn't exist",
			validationMode:        validation.AnalysisGateMode,
			admissionRequest:      podAdmissionRequest(t, nonexistentImageName),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "analysis mode: first image doesn't exist, second image has been analyzed",
			validationMode:        validation.AnalysisGateMode,
			admissionRequest:      podAdmissionRequest(t, nonexistentImageName, passingImageName),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "analysis mode: first image has been analyzed, second image doesn't exist",
			validationMode:        validation.AnalysisGateMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName, nonexistentImageName),
			isExpectedToBeAllowed: false,
		},

		{
			name:                  "passive mode: image exists, image passes",
			validationMode:        validation.BreakGlassMode,
			admissionRequest:      podAdmissionRequest(t, passingImageName),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "passive mode: image doesn't exist",
			validationMode:        validation.BreakGlassMode,
			admissionRequest:      podAdmissionRequest(t, nonexistentImageName),
			isExpectedToBeAllowed: true,
		},
		// Deployment resource tests
		{
			name:                  "policy mode: deployment with passing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      deploymentAdmissionRequest(t, newPod(t, passingImageName)),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "policy mode: deployment with failing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      deploymentAdmissionRequest(t, newPod(t, failingImageName)),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: deployment with passing image and failing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      deploymentAdmissionRequest(t, newPod(t, passingImageName, failingImageName)),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: deployment with failing image and passing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      deploymentAdmissionRequest(t, newPod(t, failingImageName, passingImageName)),
			isExpectedToBeAllowed: false,
		},
		// Job resource tests
		{
			name:                  "policy mode: job with passing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      jobAdmissionRequest(t, newPod(t, passingImageName)),
			isExpectedToBeAllowed: true,
		},
		{
			name:                  "policy mode: job with failing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      jobAdmissionRequest(t, newPod(t, failingImageName)),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: job with passing image and failing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      jobAdmissionRequest(t, newPod(t, passingImageName, failingImageName)),
			isExpectedToBeAllowed: false,
		},
		{
			name:                  "policy mode: job with failing image and passing image",
			validationMode:        validation.PolicyGateMode,
			admissionRequest:      jobAdmissionRequest(t, newPod(t, failingImageName, passingImageName)),
			isExpectedToBeAllowed: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// arrange
			anchoreService := mockAnchoreService()
			defer anchoreService.Close()

			hook := Hook{
				Config:      mockControllerConfiguration(testCase.validationMode, anchoreService),
				Clientset:   &kubernetes.Clientset{},
				AnchoreAuth: mockAnchoreAuthConfig(),
			}

			// act
			admissionResponse := hook.Validate(&testCase.admissionRequest)

			// assert
			assert.Equal(t, testCase.isExpectedToBeAllowed, admissionResponse.Allowed)
		})
	}
}

func newPod(t *testing.T, images ...string) v1.Pod {
	t.Helper()

	if len(images) == 0 {
		t.Fatal("cannot mock pods with zero images")
	}

	var containers []v1.Container

	for i, image := range images {
		containers = append(containers, v1.Container{
			Name:    fmt.Sprintf("Container-%d", i),
			Image:   image,
			Command: []string{"bin/bash", "bin"},
		})
	}

	return v1.Pod{
		ObjectMeta: testPodObjectMeta,
		Spec: v1.PodSpec{
			Containers: containers,
		},
	}
}

func newDeployment(t *testing.T, pod v1.Pod) appsV1.Deployment {
	t.Helper()

	deploymentSpec := appsV1.DeploymentSpec{
		Template: v1.PodTemplateSpec{
			Spec: pod.Spec,
		},
	}

	return appsV1.Deployment{
		ObjectMeta: testDeploymentObjectMeta,
		Spec:       deploymentSpec,
	}
}

func newJob(t *testing.T, pod v1.Pod) batchV1.Job {
	t.Helper()

	jobSpec := batchV1.JobSpec{
		Template: v1.PodTemplateSpec{
			Spec: pod.Spec,
		},
	}

	return batchV1.Job{
		ObjectMeta: testJobObjectMeta,
		Spec:       jobSpec,
	}
}

func newCronJob(t *testing.T, pod v1.Pod) batchV1beta.CronJob {
	t.Helper()

	cronJobSpec := batchV1beta.CronJobSpec{
		JobTemplate: batchV1beta.JobTemplateSpec{
			ObjectMeta: testDeploymentObjectMeta,
			Spec: batchV1.JobSpec{
				Template: v1.PodTemplateSpec{
					Spec: pod.Spec,
				},
			},
		},
	}

	return batchV1beta.CronJob{
		ObjectMeta: testDeploymentObjectMeta,
		Spec:       cronJobSpec,
	}
}

func mockControllerConfiguration(mode validation.Mode, testServer *httptest.Server) *ControllerConfiguration {
	return &ControllerConfiguration{
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

func mockAnchoreAuthConfig() *anchore.AuthConfiguration {
	return &anchore.AuthConfiguration{
		Users: []anchore.Credential{
			{"admin", "password"},
		},
	}
}

func podAdmissionRequest(t *testing.T, images ...string) v1beta1.AdmissionRequest {
	t.Helper()

	pod := newPod(t, images...)
	return newAdmissionRequest(t, pod, podKind)
}

func deploymentAdmissionRequest(t *testing.T, pod v1.Pod) v1beta1.AdmissionRequest {
	t.Helper()

	deployment := newDeployment(t, pod)
	return newAdmissionRequest(t, deployment, deploymentKind)
}

func jobAdmissionRequest(t *testing.T, pod v1.Pod) v1beta1.AdmissionRequest {
	t.Helper()

	job := newJob(t, pod)
	return newAdmissionRequest(t, job, jobKind)
}

func cronJobAdmissionRequest(t *testing.T, pod v1.Pod) v1beta1.AdmissionRequest {
	t.Helper()

	job := newCronJob(t, pod)
	return newAdmissionRequest(t, job, jobKind)
}

func newAdmissionRequest(t *testing.T, requestedObject interface{}, kind metav1.GroupVersionKind) v1beta1.AdmissionRequest {
	t.Helper()

	marshalledObject, err := json.Marshal(requestedObject)
	if err != nil {
		t.Fatal(err)
	}

	return v1beta1.AdmissionRequest{
		UID:         "abc123",
		Kind:        kind,
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

var (
	podKind = metav1.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "Pod",
	}
	deploymentKind = metav1.GroupVersionKind{
		Group:   appsV1.SchemeGroupVersion.Group,
		Version: appsV1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	}
	jobKind = metav1.GroupVersionKind{
		Group:   batchV1.SchemeGroupVersion.Group,
		Version: batchV1.SchemeGroupVersion.Version,
		Kind:    "Job",
	}
	testPodObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_pod",
		Namespace: "namespace1",
	}
	testDeploymentObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_deployment",
		Namespace: "namespace1",
	}
	testJobObjectMeta = metav1.ObjectMeta{
		Labels: map[string]string{
			"key": "value",
		},
		Annotations: map[string]string{
			"annotation1": "value1",
		},
		Name:      "a_job",
		Namespace: "namespace1",
	}
)

const (
	passingImageName     = "alpine"
	failingImageName     = "bad-alpine"
	nonexistentImageName = "ubuntu"
	passingImageDigest   = "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b"
	failingImageDigest   = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	passingStatus        = "pass"
	failingStatus        = "fail"
)

const (
	imageNotFound = `
{
  "message": "could not get image record from anchore"
}
`
	imageLookupError = `{"detail": {}, "httpcode": 404, "message": "image data not found in DB" }`
)
