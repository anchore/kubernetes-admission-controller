package main

import (
	"encoding/json"
	"fmt"
	log "github.com/golang/glog"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfig(t *testing.T) {
	c, err := loadConfig("conf.json")
	if err == nil {
		t.Log("Got config: ", c)
	} else {
		t.Error(err)
		t.Fail()
	}
}

func TestValidate(t *testing.T) {
	//Setup test service
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/images" {
			switch r.URL.Path {
			case "/images/sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b/check":
				fmt.Fprintln(w, GoodPassResponse)
			default:
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, ImageNotFound)
			}
		} else {
			switch r.URL.Query().Get("fulltag") {
			case "docker.io/alpine":
				fmt.Fprintln(w, GoodFailResponse)
			case "alpine":
				fmt.Fprintln(w, GoodFailResponse)
			case "docker.io/alpine:latest":
				fmt.Fprintln(w, GoodFailResponse)
			default:
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, ImageLookupError)
			}
		}
	}))

	defer ts.Close()


	testConf := ControllerConfiguration{
		ValidatorConfiguration{true, true, 100, true},
		MutatorConfiguration{true, "policy-evaluation-status.anchore.com"},
		AnchoreClientConfiguration{ts.URL, "admin", "foobar", false},
	}

	log.Info(fmt.Sprintf("URL: %s", ts.URL))

	InitializeClient(testConf)


	tpod := &v1.Pod{
		Spec: v1.PodSpec{Containers: []v1.Container{
			{
				Name:    "Container1",
				Image:   "alpine",
				Command: []string{"bin/bash", "bin"},
			},
		},
		},
	}

	marshalledPod, err := json.Marshal(tpod)

	if (err != nil ) {
		log.Error("Failed marshalling pod spec")
		t.Error("Failed marshalling")
	}

	admSpec := v1beta1.AdmissionRequest {
		UID: "abc123",
		Kind: metav1.GroupVersionKind{Group: v1beta1.GroupName, Version: v1beta1.SchemeGroupVersion.Version, Kind: "Pod"},
		Resource: metav1.GroupVersionResource{Group: metav1.GroupName, Version: "v1", Resource: "pods"},
		SubResource: "someresource",
		Name: "somename",
		Namespace: "default",
		Operation: "CREATE",
		Object: runtime.RawExtension{Raw: marshalledPod},
	}

	adm := admissionHook{}
	resp := adm.Validate(&admSpec)
	obj, err := json.Marshal(resp)

	if(err == nil) {
		fmt.Println(string(obj[:]))
	}

}

var GoodPassResponse = `
[
  {
    "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b": {
      "docker.io/alpine:latest": [
        {
          "detail": {},
          "last_evaluation": "2018-12-03T17:46:13Z",
          "policyId": "2c53a13c-1765-11e8-82ef-23527761d060",
          "status": "pass"
        }
      ]
    }
  }
]
`
var GoodFailResponse = `
[
  {
    "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b": {
      "docker.io/alpine:latest": [
        {
          "detail": {},
          "last_evaluation": "2018-12-03T17:46:13Z",
          "policyId": "2c53a13c-1765-11e8-82ef-23527761d060",
          "status": "fail"
        }
      ]
    }
  }
]
`

var ImageNotFound = `
{  
  "message": "could not get image record from anchore"
}
`

var PolicyNotFound = `
{
    "detail": {},
    "httpcode": 404,
    "message": "Policy bundle notreal not found in DB"
}
`

var ImageLookup = `
[
  {
    "analysis_status": "analyzed",
    "analyzed_at": "2018-12-03T18:24:54Z",
    "annotations": {},
    "created_at": "2018-12-03T18:24:43Z",
    "imageDigest": "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b",
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
        "digest": "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b",
        "dockerfile": "RlJPTSBzY3JhdGNoCkFERCBmaWxlOjI1YzEwYjFkMWI0MWQ0NmExODI3YWQwYjBkMjM4OWMyNGRmNmQzMTQzMDAwNWZmNGU5YTJkODRlYTIzZWJkNDIgaW4gLyAKQ01EIFsiL2Jpbi9zaCJdCg==",
        "fulldigest": "docker.io/alpine@sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b",
        "fulltag": "docker.io/alpine:latest",
        "imageDigest": "sha256:02892826401a9d18f0ea01f8a2f35d328ef039db4e1edcc45c630314a0457d5b",
        "imageId": "196d12cf6ab19273823e700516e98eb1910b03b17840f9d5509f03858484d321",
        "last_updated": "2018-12-03T18:24:54Z",
        "registry": "docker.io",
        "repo": "alpine",
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
`

var ImageLookupError = `{"detail": {}, "httpcode": 404, "message": "image data not found in DB" }`


func TestLookupImage(t *testing.T) {
	log.Info("Testing image lookup handling")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/images" {
			fmt.Fprint(w,"Ok")

		} else {
			switch r.URL.Query().Get("fulltag") {
			case "docker.io/alpine:latest":
				fmt.Fprintln(w, GoodFailResponse)
			default:
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, ImageLookupError)
			}
		}
	}))

	defer ts.Close()

	log.Info(fmt.Sprintf("URL: %s", ts.URL))

	testConf := ControllerConfiguration{
		ValidatorConfiguration{true, true, 100, true},
		MutatorConfiguration{true, "policy-evaluation-status.anchore.com"},
		AnchoreClientConfiguration{ts.URL, "admin", "foobar", false},
	}

	client, authCtx, err := initClient(testConf)

	if err != nil {
		log.Fatal(err)
	}

	localOpts := make(map[string]interface{})

	var calls = [][]string{{"docker.io/alpine", "analyzed"}, {"docker.io/alpine:3.8", "notfound"}}
	var result string

	for _, item := range calls {
		log.Info(fmt.Sprintf("Checking %s", item))
		localOpts["fulltag"] = item[0]
		imageListing, _, err := client.AnchoreEngineApi.ListImages(authCtx, localOpts)
		if err != nil {
			if item[1] == "notfound" {
				log.Info("Expected error response from server: ", err)

			} else {
				log.Error(err)
				assert.Fail(t, "Did not expect an error")
			}
			continue
		}

		fmt.Printf("Images: %s\n", imageListing)
		result = imageListing[0].AnalysisStatus
		fmt.Printf("Result: %s\n", result)
		if result != item[1] {
			log.Info(fmt.Sprintf("Expected %s but got %s", item[1], result))
			t.Fail()
		}
	}
}

/*
Test the CheckImage function against some fake responses
 - Successful policy eval
 - Error during policy eval
 - Image not found
 - Bundle not found

 */
func TestCheckImage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/images/goodfail/check":
			fmt.Fprintln(w, GoodFailResponse)
		case "/images/goodpass/check":
			fmt.Fprintln(w, GoodPassResponse)
		case "/images/imagenotfound/check":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, ImageNotFound)
		case "/images/policynotfound/check":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, ImageNotFound)
		default:
			fmt.Fprint(w, r.URL.Path)
		}
	}))

	defer ts.Close()

	log.Info(fmt.Sprintf("URL: %s", ts.URL))

	testConf := ControllerConfiguration{
		ValidatorConfiguration{true, true, 100, true},
		MutatorConfiguration{true, "policy-evaluation-status.anchore.com"},
		AnchoreClientConfiguration{ts.URL, "admin", "foobar", false},
	}

	client, authCtx, err := initClient(testConf)

	if err != nil {
		log.Fatal(err)
	}

	localOpts := make(map[string]interface{})

	var calls = [][]string{{"goodpass", "pass"}, {"goodfail", "fail"}, {"imagenotfound", "notfound"}, {"policynotfound", "notfound"}}
	var result string

	for _, item := range calls {

		log.Info(fmt.Sprintf("Checking %s", item))
		policyEvaluations, _, err := client.AnchoreEngineApi.GetImagePolicyCheck(authCtx, item[0], "docker.io/alpine", localOpts)
		if err != nil {
			if item[1] == "notfound" {
				log.Info("Expected error response from server: ", err)

			} else {
				log.Error(err)
				assert.Fail(t, "Did not expect an error")
			}
			continue
		}

		fmt.Printf("Policy evaluation: %s\n", policyEvaluations)
		result = findResult(policyEvaluations[0])
		fmt.Printf("Result: %s\n", result)
		if result != item[1] {
			log.Info(fmt.Sprintf("Expected %s but got %s", item[1], result))
			t.Fail()
		}
	}

}
