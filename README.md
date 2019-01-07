# Anchore Kubernetes Admission Controller

This controller is based on the [openshift generic admission controller](https://github.com/openshift/generic-admission-server).

It implements a Kubernetes Dynamic Webhook controller for interacting with Anchore Engine and making admission decisions based image properties as determined during
analysis by [Anchore Engine](https://github.com/anchore/anchore-engine).

The Anchore admission controller supports 3 different modes of operation allowing you to tune tradeoff between control and intrusiveness for your environments. 

### Strict Policy-Based Admission Gating Mode
This is the strictest mode, and will admit only images that are already analyzed by Anchore and receive a "pass" on policy evaluation. This enables you to
ensure, for example, that no image is deployed into the cluster that has a known high-severity CVE with an available fix, or any of a number of other conditions.
Anchore's policy language (found [here](https://anchore.freshdesk.com/support/solutions/articles/36000074705-policy-bundles-and-evaluation)) supports sophisticated conditions on the properties of images, vulnerabilities, and metadata.
If you have a check or condition that you want to evaluate that you're not sure about, please let us [know](https://github.com/anchore/anchore-engine/issues)!

Examples of Anchore Engine policy rules that are useful in a strict admission environment:
* Reject an image if it is being pulled from dockerhub directly
* Reject an image that has high or critical CVEs that have a fix available, but allow high-severity if no fix is available yet
* Reject an image if it contains a blacklisted package (rpm, deb, apk, jar, python, npm, etc), where you define the blacklist
* Never reject images from a specific registry/repository (e.g. internal infra images that must be allowed to run)

### Analysis-Based Admission Gating Mode
Admit only images that are analyzed and known to Anchore, but do not execute or require a policy evaluation. This is useful in cases where
you'd like to enforce requirement that all images be deployed via a CI/CD pipeline, for example, that itself manages the image scanning with Anchore, but allowing the
CI/CD process to determine what should run based on other factors outside the context of the image or k8s itself.

### Passive Analysis Trigger Mode
Trigger an Anchore analysis of images, but to no block execution on analysis completion or policy evaluation of the image. This is a way to ensure that all images
that make it to deployment (test, staging, or prod) are guaranteed to have some form of analysis audit trail available and a presence in reports and notifications
that are managed by Anchore Engine. Image records in Anchore Engine are given an annotation of "requestor=anchore-admission-controller" to
help track their provenance.


## Deploy

The default way to deploy it is with a [Helm Chart](https://github.com/anchore/anchore-charts/tree/master/stable/anchore-admission-controller), see the chart README for more details.

## Build

`docker build -t tag .` Should be all that is necessary to build.
 
## Environment Variables

_CONFIG_FILE_PATH_ - Path to the config file. The server will use _/config.json_ unless this is set.
_ANCHORE_USERNAME_ - Username for the anchore http client, overrides the config file value
_ANCHORE_PASSWORD_ - Password for the anchore http client, overrides the config file value

## Configuration File

The server loads the configuration from the _CONFIG_FILE_PATH_ location (defaults to _/config.json_)



type AnchoreClientConfiguration struct {
	Endpoint            string
	Username            string
	Password            string
	PolicyBundle        string
	//VerifyCert          bool
}

type ValidatorConfiguration struct {
	Enabled             bool
	RequireImageAnalyzed bool
	RequirePassPolicy   bool
	RequestAnalysis     bool
}

The configuration is a json file. Example:
```
{
  "validator": {
    "enabled": true,
    "requireimageanalyzed": false,
    "requirepasspolicy": true,
    "requestanalysis": true
  },
  "client": {
    "endpoint": "http://localhost:8228",
    "username": "admin",
    "password": "foobar",
    "policybundle": "test123"
  }
}
```


### Validator Config Details
* _requirepasspolicy_ - boolean, overrides the other values. If true, all images in the spec must already be analyzed by the Anchore Engine and must pass policy evaluation of the configured policy. Which policy to use is specified in config by _policybundle_.
* _requireanalyzed_ - boolean. overrides _requestanalysis_ and if set admission will only occur if all images in the spec have been analyzed by Anchore Engine.
* _requestanalysis_ - boolean. If set and the above two conditions do not hold (either set to false or fail in evaluation) then the controller will request an image be analyzed by the Engine, but not block for completion.

### Client Config
* _policybundle_ - String. The policy bundle id to evaluate. If unset, the evaluation will use the user's active bundle in Anchore Engine, which is configured in the Engine, not in the admission controller.

