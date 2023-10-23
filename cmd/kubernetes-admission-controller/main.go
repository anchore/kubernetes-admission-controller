/*
The main entry point for the Anchore Kubernetes Admission Controller

This controller, based on the openshift generic admission server), supports Validating Webhook requests

Default behavior is ValidatingAdmissionWebhook-only mode

Configuration:
The controller relies on a pair of config inputs:
1.) Configuration json in a file, typically provided via mounted ConfigMap. Defaults to filename /config.json. Overridden by env var CONFIG_FILE_PATH
2.) Anchore client credentials, typically provided via a mounted file from a Secret, also json format. Defaults to filename /credentials.json. Overridden by env var CREDENTIALS_FILE_PATH

*/

package main

import (
	"flag"
	"os"
	"strings"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/admission"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"github.com/fsnotify/fsnotify"
	"github.com/openshift/generic-admission-server/pkg/cmd"
	"github.com/spf13/viper"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

var (
	authVpr                 *viper.Viper
	confVpr                 *viper.Viper
	controllerConfiguration admission.ControllerConfiguration
	authConfiguration       anchore.AuthConfiguration
)

var clientset *kubernetes.Clientset

const (
	credsConfigFilePathEnvVar string = "CREDENTIALS_FILE_PATH"
	configFilePathEnvVar      string = "CONFIG_FILE_PATH"
	versionCheckDisabled      string = "VERSION_CHECK_DISABLED"
)

func updateConfig(fsnotify.Event) {
	klog.Info("Detected update event to the configuration file. Will reload")
	err := confVpr.ReadInConfig()
	if err != nil {
		klog.Error("Error updating configuration. err=", err)
	}
	err = confVpr.Unmarshal(&controllerConfiguration)
	if err != nil {
		klog.Error("Error updating configuration. err=", err)
	}
}

func updateAuthConfig(fsnotify.Event) {
	klog.Info("Detected update event to the configuration file. Will reload")
	err := authVpr.ReadInConfig()
	if err != nil {
		klog.Error("Error updating auth configuration. err=", err)
	}
	err = authVpr.Unmarshal(&authConfiguration)
	if err != nil {
		klog.Error("Error updating auth configuration. err=", err)
	}
}

func getEnvWithDefault(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	klog.InitFlags(nil)
	// Hack to fix an issue with log that makes log lines prefixed with: "logging before flag.Parse:". Do not want that
	_ = flag.CommandLine.Parse([]string{})

	klog.Info("Version: ", FromBuild())
	// Configure
	klog.Info("Initializing configuration")
	configPath, found := os.LookupEnv(configFilePathEnvVar)

	if !found {
		configPath = "/config.json"
	}

	authPath, authFound := os.LookupEnv(credsConfigFilePathEnvVar)
	if !authFound {
		authPath = "/credentials.json"
	}

	klog.Info("Loading configuration from ", configPath)
	confVpr = viper.New()
	confVpr.SetConfigFile(configPath)
	err := confVpr.ReadInConfig()
	if err != nil {
		klog.Error("Could not load configuration err=", err)
		panic(err.Error())
	}

	err = confVpr.Unmarshal(&controllerConfiguration)
	if err != nil {
		klog.Error("Error unmarshalling configuration err=", err)
		panic(err.Error())
	}

	confVpr.OnConfigChange(updateConfig)
	confVpr.WatchConfig()

	klog.Info("Loading creds from ", authPath)
	authVpr = viper.New()
	authVpr.SetConfigFile(authPath)
	err = authVpr.ReadInConfig()
	if err != nil {
		klog.Error("Could not load auth configuration err=", err)
		panic(err.Error())
	}

	err = authVpr.Unmarshal(&authConfiguration)
	if err != nil {
		klog.Error("Error unmarshalling auth configuration err=", err)
		panic(err.Error())
	}
	authVpr.OnConfigChange(updateAuthConfig)
	authVpr.WatchConfig()

	// creates client with in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Error("Error building in-cluster config for k8s client err=", err)
		panic(err.Error())
	}

	// creates the clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		klog.Error("Error getting k8s client err=", err)
		panic(err.Error())
	}

	var imageBackend anchore.ImageBackend
	imageBackend, err = anchore.NewAPIImageBackend(controllerConfiguration.AnchoreEndpoint)
	if err != nil && strings.ToLower(getEnvWithDefault(versionCheckDisabled, "false")) == "false" {
		klog.Info("Error creating image backend err=", err)
		klog.Info("Falling back to API Image Backend for API v1")
		// Try to use the old API Image Backend that supports Anchore API v1
		imageBackend, err = anchore.NewAPIImageBackendV1(controllerConfiguration.AnchoreEndpoint)
		if err != nil {
			klog.Error("Error creating image backend err=", err)
			panic(err.Error())
		}
	}

	hook := admission.NewHook(&controllerConfiguration, clientset, &authConfiguration, imageBackend)

	klog.Info("Starting server")

	// Run the server
	cmd.RunAdmissionServer(hook)
}
