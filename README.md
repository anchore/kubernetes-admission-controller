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


## Build

`docker build -t tag .` Should be all that is necessary to build.
 

## Configuration

The server itself looks for a config file in either `/config.json` or wherever `CONFIG_FILE_PATH` environment variable indicates.

That file should be a json file. Example:
```
{
  "validator": {
    "enabled": true,
    "analyzeIfNotPresent": false,
    "analyzeTimeout": 0,
    "validateStatus": true
  },
  "client": {
    "endpoint": "http://localhost:8228",
    "username": "admin",
    "password": "foobar",
    "policybundle": "test123"
  }
}
```