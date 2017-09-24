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

type CertConfigOutput struct {
	File  CertConfigFile `yaml:"file"`
	Items []string       `yaml:"items"`
}

type CertConfigFile struct {
	Type string      `yaml:"type"`
	Name string      `yaml:"name"`
	Perm os.FileMode `yaml:"perm"`
}

type CertConfig struct {
	CommonName     string           `yaml:"commonName"`
	AlternateNames []string         `yaml:"alternateNames"`
	ReloadCommand  string           `yaml:"reloadCommand"`
	User           string           `yaml:"user"`
	Group          string           `yaml:"group"`
	TTL            time.Duration    `yaml:"ttl"`
	RenewTTL       time.Duration    `yaml:"renewTtl"`
	Output         CertConfigOutput `yaml:"output"`
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

func (c CertConfig) Validate() error {
	var err error
	check := func(validator func() error) {
		if err != nil {
			return
		}
		err = validator()
	}

	check(c.validateCommonName)
	check(c.validateTTL)

	return err
}

func (c CertConfig) validateCommonName() error {
	if c.CommonName == "" {
		return fmt.Errorf("commonName is not set")
	}
	return nil
}

func (c CertConfig) validateTTL() error {
	if c.RenewTTL == 0 {
		return fmt.Errorf("renewTtl is not set")
	}

	if c.TTL == 0 {
		return fmt.Errorf("ttl is not set")
	}

	if c.RenewTTL >= c.TTL {
		return fmt.Errorf("renewTtl cannot be greater or equal than TTL")
	}
	return nil
}

func LoadMainConfig(configPath string) (*MainConfig, error) {
	mainConfig := MainConfig{}

	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	if err := yaml.UnmarshalStrict(content, &mainConfig); err != nil {
		return nil, err
	}

	return &mainConfig, nil
}

func (mainConfig MainConfig) LoadConfigDirs(certConfigPath string) ([]CertConfig, error) {
	var certConfigs = make([]CertConfig, 0, 10)
	var retErr error

	includePaths := mainConfig.IncludePaths
	if certConfigPath != "" {
		includePaths = []string{certConfigPath}
	}

	log.Printf("Loading certificate paths: %v", includePaths)
	for _, path := range includePaths {
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
			if err := certConfig.Validate(); err != nil {
				log.Printf("Error validating certificate configuration %s: %v", file, err)
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
