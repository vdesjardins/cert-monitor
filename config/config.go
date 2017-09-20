package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type MainConfig struct {
	Vault struct {
		RoleId    string `yaml:"roleId"`
		SecretId  string `yaml:"secretId"`
		BaseUrl   string `yaml:"baseUrl"`
		LoginPath string `yaml:"loginPath"`
		CertPath  string `yaml:"certPath"`
	} `yaml:"vault"`
	IncludePaths       []string      `yaml:"includePaths"`
	DownloadedCertPath string        `yaml:"downloadedCertPath"`
	CheckInterval      time.Duration `yaml:"checkInterval"`
}

type CertConfig struct {
	CommonName     string   `yaml:"commonName"`
	AlternateNames []string `yaml:"alternateNames"`
	ReloadCommand  string   `yaml:"reloadCommand"`
	User           string   `yaml:"user"`
	Group          string   `yaml:"group"`
	Output         struct {
		File struct {
			Type string      `yaml:"type"`
			Name string      `yaml:"name"`
			Perm os.FileMode `yaml:"perm"`
		} `yaml:"file"`
		Items []string `yaml:"items"`
	} `yaml:"output"`
}

func (c CertConfig) GroupId() (string, error) {
	if c.Group != "" {
		group, err := user.LookupGroup(c.Group)
		if err != nil {
			return "", fmt.Errorf("Error: %v", err)
		}

		return group.Gid, nil
	}

	group, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Error: %v", err)
	}

	return group.Gid, nil
}

func (c CertConfig) UserId() (string, error) {

	if c.User != "" {
		user, err := user.Lookup(c.User)
		if err != nil {
			return "", fmt.Errorf("Error: %v", err)
		}

		return user.Uid, nil
	}

	user, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Error: %v", err)
	}

	return user.Uid, nil
}

func LoadMainConfig(configPath string) (*MainConfig, error) {
	mainConfig := MainConfig{}

	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return nil, err
	}
	if err := yaml.UnmarshalStrict(content, &mainConfig); err != nil {
		log.Printf("Error parsing YAML file: %v", err)
		return nil, err
	}

	return &mainConfig, nil
}

func (mainConfig MainConfig) LoadConfigDirs() ([]CertConfig, error) {
	var certConfigs = make([]CertConfig, 0, 10)
	var retErr error

	log.Printf("Loading certificate paths: %v", mainConfig.IncludePaths)
	for _, path := range mainConfig.IncludePaths {
		files, err := filepath.Glob(path)

		if err != nil {
			log.Printf("Error globbing path %s: %v", path, err)
			continue
		}

		for _, file := range files {
			log.Printf("Loading certificate file %s", file)

			if filepath.Ext(file) != ".yml" && filepath.Ext(file) != ".yaml" {
				log.Printf("Ignoring file %s", file)
				continue
			}

			var certConfig = CertConfig{}

			log.Printf("Loading file %s", file)
			content, err := ioutil.ReadFile(file)
			if err != nil {
				log.Printf("Error reading file %s: %v", file, err)
				retErr = err
				continue
			}
			if err := yaml.UnmarshalStrict(content, &certConfig); err != nil {
				log.Printf("Error parsing YAML content for file %s: %v", file, err)
				retErr = err
				continue
			}
			certConfigs = append(certConfigs, certConfig)
		}

		if err != nil {
			retErr = err
		}
	}

	return certConfigs, retErr
}

func visitFile(path string, info os.FileInfo, err error) error {
	var certConfig = CertConfig{}

	if filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml" {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("Error reading file %s: %v", path, err)
			return nil
		}
		if err := yaml.UnmarshalStrict(content, &certConfig); err != nil {
			log.Printf("Error parsing YAML content for file %s: %v", path, err)
			return nil
		}
	}
	return nil
}
