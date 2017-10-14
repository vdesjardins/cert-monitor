package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"time"

	yaml "gopkg.in/yaml.v2"
)

const (
	certFileName = "cert.pem"
)

type VaultConfig struct {
	RoleId    string `yaml:"roleId"`
	SecretId  string `yaml:"secretId"`
	BaseUrl   string `yaml:"baseUrl"`
	LoginPath string `yaml:"loginPath"`
	CertPath  string `yaml:"certPath"`
}

type MainConfig struct {
	Vault              VaultConfig   `yaml:"vault"`
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
	MainConfig     *MainConfig
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

func (m MainConfig) ResolveConfigDirs() ([]string, error) {
	var errorString string
	var dirs []string

	for _, path := range m.IncludePaths {
		files, err := filepath.Glob(path)

		if err != nil {
			errorString = fmt.Sprintf("%vError reading glob path %v\n", errorString, path)
		}
		dirs = append(dirs, files...)
	}
	if errorString != "" {
		return dirs, fmt.Errorf("Error loading config directories: %v", errorString)
	}

	return dirs, nil
}

func (m MainConfig) LoadCertConfig(file string) (CertConfig, error) {
	var certConfig = CertConfig{MainConfig: &m}

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return certConfig, fmt.Errorf("Error reading file '%v': %v", file, err)
	}
	if err := yaml.UnmarshalStrict(content, &certConfig); err != nil {
		return certConfig, fmt.Errorf("Error parsing YAML content for file '%s': %v", file, err)
	}
	if err := certConfig.Validate(); err != nil {
		return certConfig, fmt.Errorf("Error validating certificate configuration '%s': %v", file, err)
	}

	return certConfig, nil
}

func (c CertConfig) IsExpired() bool {

	cert, err := c.LoadCachedCertificate()
	if err != nil {
		return true
	}

	cutoffTime := cert.NotAfter.Add(-c.RenewTTL)

	if time.Now().After(cutoffTime) {
		return true
	}

	return false
}

func (c CertConfig) LoadCachedCertificate() (*x509.Certificate, error) {
	certFile := path.Join(c.MainConfig.DownloadedCertPath, c.CommonName, certFileName)

	if _, err := os.Stat(c.Output.File.Name); err != nil {
		return nil, err
	}

	if _, err := os.Stat(certFile); err != nil {
		return nil, err
	}

	content, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(content))
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
