#!/bin/bash

# This script sets up a dev environment for using skaffold to run/test the controller

if ! helm --help
then
	echo Helm must be installed and configured.
	exit 1
fi

if ! helm repo list | grep charts.anchore.io
then
	echo Helm must be configured to have the Anchore Charts repo
	echo To add the repo use: "helm repo add anchore-stable http://charts.anchore.io/stable ; helm repo update"
fi

helm fetch --untar anchore-stable/anchore-admission-controller

