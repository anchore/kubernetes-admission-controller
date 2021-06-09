# Changelog

## v0.3.0

**Breaking change: Changes the "ResourceType" value from "pod" to "resource" in the selector configuration. This is to clarify that metadata match will be against the resource being validated, which may not be a Pod, but another kind such as Deployment or ReplicaSet.**

- Adds support for additional resource validation beyond Pods. Now supports all workload resources in K8s.
- Significant internal refactoring and added testing
- Improved logging
