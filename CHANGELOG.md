# Changelog

## v0.3.0

- Adds support for additional resource validation beyond Pods. Now supports all workload resources in K8s.
- Changes the "ResourceType" value from "pod" to "resource" in configuration to clarify that metadata match will be against the resource being validated, which may not be a Pod, but another kind such as Deployment or ReplicaSet.
- Significant internal refactoring and added testing
- Improved logging
