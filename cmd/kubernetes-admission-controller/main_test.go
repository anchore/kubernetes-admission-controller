package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/admission"
	"github.com/anchore/kubernetes-admission-controller/cmd/kubernetes-admission-controller/anchore"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

func TestConfigUpdate(t *testing.T) {
	var tmp admission.ControllerConfiguration
	configFileName := filepath.Join("testdata", "test_conf_init.json")

	src, ferr := os.Open(configFileName)
	if ferr != nil {
		t.Fatal(ferr, "Cannot find input config file")
	} else {
		defer src.Close()
	}

	tmpFileName := filepath.Join("testdata", "tmp_test_conf.json")
	dest, ferr2 := os.Create(tmpFileName)
	if ferr2 != nil {
		t.Fatal(ferr2, "Cannot open new tmp file")
	} else {
		defer dest.Close()
		defer os.Remove(tmpFileName)
	}

	_, ferr = io.Copy(dest, src)
	if ferr != nil {
		t.Fatal(ferr, "Could not create a copy of the config file for testing")
	}

	t.Log("Reading initial config")
	v := viper.New()
	v.SetConfigFile(tmpFileName)
	err := v.ReadInConfig()
	if err != nil {
		t.Fatal(err)
	}

	if v.Unmarshal(&tmp) != nil {
		t.Fatal(err)
	} else {
		cfg, _ := json.Marshal(tmp)
		t.Log("Got initial update test config: ", string(cfg))
	}

	v.OnConfigChange(func(in fsnotify.Event) {
		t.Log("Detected update and reloading!")
		if err = v.ReadInConfig(); err != nil {
			t.Fatal(err)
		}

		if err = v.Unmarshal(&tmp); err != nil {
			t.Fatal(err)
		}
	})

	t.Log("Watching the config")
	v.WatchConfig()

	var enabled bool

	t.Log("Starting the update cycler")
	for counter := 0; counter < 10; counter++ {
		t.Log("Waiting ", counter, " out of 10")
		time.Sleep(time.Duration(1 * time.Second))

		t.Log("Current config enabled flag: ", tmp.Validator.Enabled)
		enabled = tmp.Validator.Enabled

		if counter%2 != 0 {
			// Update the file, should cause a reload
			tmp2 := tmp
			tmp2.Validator.Enabled = !enabled
			tmpBytes, err := json.Marshal(tmp2)
			if err != nil {
				t.Fatal(err)

			}

			if len(tmpBytes) <= 0 {
				t.Fatal("No bytes found from marshalled struct")
			} else {
				t.Log("Updated config to write: ", string(tmpBytes))
			}

			t.Log("Writing updated config")
			fd, err := os.Create(tmpFileName)
			if err != nil {
				t.Fatal(err)

			}

			_, err = fd.Write(tmpBytes)
			if err != nil {
				t.Fatal(err)

			}

			if err = fd.Close(); err != nil {
				t.Fatal(err)

			}
		}
	}

	t.Log("Sleeping 1s to let things flush and close cleanly")
	time.Sleep(1 * time.Second)

	t.Log("Complete")
}

func TestConfig(t *testing.T) {
	v := viper.New()
	f, _ := os.Getwd()
	t.Log(f)
	configPath := filepath.Join("testdata", "test_conf.json")
	v.SetConfigFile(configPath)
	err := v.ReadInConfig()
	if err != nil {
		t.Fatal(err)

	}
	t.Log("Cfg State: ", v)
	var tmp admission.ControllerConfiguration
	err = v.Unmarshal(&tmp)
	if err != nil {
		t.Fatal(err)

	} else {
		cfg, _ := json.Marshal(tmp)
		t.Log("Got config: ", string(cfg))
	}

	var tmp2 anchore.AuthConfiguration
	v = viper.New()
	configPath2 := filepath.Join("testdata", "test_creds.json")
	v.SetConfigFile(configPath2)
	err = v.ReadInConfig()
	if err != nil {
		t.Fatal(err)

	}
	t.Log("AuthCfg State: ", v)
	err = v.Unmarshal(&tmp2)
	if err != nil {
		t.Fatal(err)

	} else {
		if len(tmp2.Users) <= 0 {
			t.Fatal("No entries found")

		}

		cfg, _ := json.Marshal(tmp2)
		t.Log("Got auth config: ", string(cfg))
	}

	v = viper.New()
	yamlCreds := filepath.Join("testdata", "test_creds.yaml")
	v.SetConfigFile(yamlCreds)
	err = v.ReadInConfig()
	if err != nil {
		t.Fatal("Could not read config")
	}
	t.Log("AuthCfg State: ", v)
	tmp2 = anchore.AuthConfiguration{}
	err = v.Unmarshal(&tmp2)
	if err != nil {
		t.Fatal(err)

	} else {
		if len(tmp2.Users) <= 0 {
			t.Fatal("No entries found")

		}

		cfg, _ := json.Marshal(tmp2)
		t.Log("Got auth config: ", string(cfg))
	}

}
