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
	IncludePath        string        `yaml:"includePath"`
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
			Perm os.FileMode `yaml:perm"`
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
		return nil, err
	}
	if err := yaml.Unmarshal(content, &mainConfig); err != nil {
		return nil, err
	}

	return &mainConfig, nil
}

func LoadConfigDir(mainConfig MainConfig) []CertConfig {
	var certConfigs = make([]CertConfig, 0, 10)

	err := filepath.Walk(mainConfig.IncludePath, func(path string, info os.FileInfo, err error) error {
		var certConfig = CertConfig{}

		if err != nil {
			log.Printf("Error reading file %s: %v", path, err)
			return nil
		}

		if filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml" {
			log.Printf("Loading file %s", path)
			content, err := ioutil.ReadFile(path)
			if err != nil {
				log.Printf("Error reading file %s: %v", path, err)
				return nil
			}
			if err := yaml.Unmarshal(content, &certConfig); err != nil {
				log.Printf("Error parsing YAML content for file %s: %v", path, err)
				return nil
			}
			certConfigs = append(certConfigs, certConfig)
		}
		return nil
	})

	if err != nil {
		log.Println("Error processing config directory %s %v", mainConfig.IncludePath, err)
		return nil
	}

	return certConfigs
}

func visitFile(path string, info os.FileInfo, err error) error {
	var certConfig = CertConfig{}

	if filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml" {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("Error reading file %s: %v", path, err)
			return nil
		}
		if err := yaml.Unmarshal(content, &certConfig); err != nil {
			log.Printf("Error parsing YAML content for file %s: %v", path, err)
			return nil
		}
	}
	return nil
}
