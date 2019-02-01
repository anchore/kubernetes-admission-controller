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

The tested way to deploy the controller is with the [Helm Chart](https://github.com/anchore/anchore-charts/tree/master/stable/anchore-admission-controller), see the chart README for more details
on its own configuration including tls/cert setup that is necessary to have the k8s apiserver contact the controller securely.

## Build

`docker build -t tag .` Should be all that is necessary to build.
 
## Environment Variables

_CONFIG_FILE_PATH_ - Path to the config file. The server will use _/config.json_ unless this is set.
_ANCHORE_USERNAME_ - Username for the anchore http client, overrides the config file value
_ANCHORE_PASSWORD_ - Password for the anchore http client, overrides the config file value



## Configuration Files

The controller uses a pair of configuration files to facilitate managing secrets in a different way than configuration.
Configuration is handled in the configuration file, while anchore user credentials are read from the credentials file, which is attached
to the container as mounted secret.

The helm chart mounts the config file at: /config/config.json and the credentials at /credentials/credentials.json

The locations of the files can be set with environment variables:
CREDENTIALS_FILE_PATH - the full file path including filename for the credential list (e.g. /credentials.json)
CONFIG_FILE_PATH - the full file path including filename for the config file (e.g. /config.json)

### Credentials Configuration
Since the mapping of an validation request can result in different policies evaluated, the controller needs a way to get
the credentials necessary to access a specific policy. The credentials config provides this as a json file (usually mounted from a secret)
The format is:
```
{
  "users": [
    {"username": "user1", "password": "password1"},
    {"username": "user2", "password": "password2"}
  ]
}

These must all be valid credentials for the endpoint specified in the configuration


```
### Controller Configuration 

The server loads the configuration from the _CONFIG_FILE_PATH_ location (defaults to _/config.json_)

The configuration is a json file that contains the selector rules and endpoint for contacting anchore engine,
the credentials are merged in from the credentials config described in the previous section.
 
Example:
```
{
  "anchoreEndpoint": "https://anchore-engine-api.anchore.svc.cluster.local:8228",
  "validator": {
    "enabled": true,
    "requestAnalysis": true
  },
  "selectors": [
    {
      "selector": {
        "resourcetype": "pod",
        "selectorkeyregex": "^breakglass$",
        "selectorvalueregex": "^true"
      },
      "policyReference": {
        "username": "user1",
        "policyBundleId": "application_bundle"
      },
      "mode": "breakglass"
      },
    {
    "selector": {
      "resourcetype": "pod",
      "selectorkeyregex": "^app$",
      "selectorvalueregex": "^demoapp.*"
    },
    "policyReference": {
      "username": "user1",
      "policyBundleId": "application_bundle"
    },
    "mode": "policy"
    },
    {
    "selector": {
      "resourcetype": "namespace",
      "selectorkeyregex": "name",
      "selectorvalueregex": "^testing$"
    },
    "policyReference": {
      "username": "user1",
      "policyBundleId": "test_bundle"
    },
    "mode": "policy",
    },
    {
    "selector": {
      "resourcetype": "image",
      "selectorkeyregex": ".*",
      "selectorvalueregex": ".*"
    },
    "policyReference": {
      "username": "user1",
      "policyBundleId": "default"
    },
    "mode": "analysis"
    }
  ]
}
```

### Validator Config Details
* _anchoreEndpoint_ - The api endpoint to send requests to. May be internal or external to the cluster running the controller, only must be reachable on the network
* _enabled_ - (currently unused) boolean. In future udpates, if false, will operate in a dry-run like mode to enable testing/debugging
* _requestanalysis_ - boolean. If set and the above two conditions do not hold (either set to false or fail in evaluation) then the controller will request an image be analyzed by the Engine, but not block for completion.


### Selectors
* _selector_ - The rule to match
* _policyReference_ - The policy to use (w/username scope) if the selector rule matches

#### Selector
* _resourceType_ - string (enum): one of "pod", "namespace", "image". Determines which metadata is used for the selection match
* _selectorKeyRegex_ - string: regex to use to select the name, or use an annotation/label for comparison of values with the next regex. 
The value "name" is treated specially for pods and namespaces where it will use the actual name rather than looking for a label/annotation with the key "name".

* _selectorValueRegex_ - string: regex to evaluate against a key-value pair (annotation or label) that was matched by the selectorKeyRegex

Selector Execution:
For namespaces and pods, as a selector is evaluated against metadata each rule is checked against all labels then all annotations before moving to the next rule.
Labels take precedence over annotations for pod/namespace metadata matches.

Example:
To select on the name of a namespace to which a pod belongs:
```
"selector": {
  "resourceType": "namespace",
  "selectorKeyRegex": "name",
  "selectorValueRegex": "testing_namespace"
} 
```

### Updating Configuration

The controller monitors the config and credential files for updates and will automatically reload them dynamically so no restart is
required to update rules or credentials.


