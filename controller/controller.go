package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vdesjardins/cert-monitor/config"
	"github.com/vdesjardins/cert-monitor/vault"
)

const (
	certFileName      = "cert.pem"
	chainFileName     = "chain.pem"
	issuingCAFileName = "issuing_ca.pem"
	privateFileName   = "private.pem"
)

func ExecOnce(configPath string, noReload bool, certConfigPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	err = execute(cfg, noReload, true, certConfigPath)
	if err != nil {
		return err
	}

	return nil
}

func ExecLoop(configPath string, noReload bool) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		cfg, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("aborting! %v", err)
		}

		execute(cfg, noReload, false, "")

		log.Printf("Check interval set to %v", cfg.CheckInterval)
		ticker := time.Tick(cfg.CheckInterval)

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		signal.Notify(sig, os.Kill)

		for {
			select {
			case <-sig:
				log.Printf("Exiting...\n")
				return
			case <-ticker:
				cfg, err := loadConfig(configPath)
				if err == nil {
					execute(cfg, noReload, false, "")
				}
			}

		}
	}()

	wg.Wait()
}

func loadConfig(configPath string) (*config.MainConfig, error) {

	cfg, err := config.LoadMainConfig(configPath)
	if err != nil {
		log.Printf("Error loading main config'%s'.\n", configPath)
		return nil, fmt.Errorf("Error loading main config: %v", err)
	}
	log.Printf("Main configuration '%s' loaded sucessefully.\n", configPath)

	return cfg, nil
}

func execute(cfg *config.MainConfig, noReload bool, failOnError bool, certConfigPath string) error {
	certConfigs, err := cfg.LoadConfigDirs(certConfigPath)
	if err != nil {
		return err
	}

	vaultCfg, err := initVaultClient(*cfg)
	if err != nil {
		log.Printf("%+v\n", err)
		return err
	}

	servicesToRestart := map[string]bool{}

	for _, certConfig := range certConfigs {
		certReq := initCertRequest(certConfig)

		if !isCertificateExpired(certConfig, *cfg) {
			continue
		}

		log.Printf("Generating certificate for commonName %v AlternateNames %v", certConfig.CommonName, certConfig.AlternateNames)
		cert, err := vaultCfg.FetchNewCertificate(certReq)
		if err != nil {
			log.Printf("%+v\n", err)
			continue
		}

		if err := persistCertificate(*cfg, certConfig, cert); err != nil {
			log.Println(err)
			continue
		}

		if noReload == false {
			servicesToRestart[certConfig.ReloadCommand] = true
		}
	}

	// restart services
	for k, _ := range servicesToRestart {
		restartService(k)
	}

	return nil
}

func initVaultClient(mainConfig config.MainConfig) (*vault.Client, error) {
	baseUrl, err := url.Parse(mainConfig.Vault.BaseUrl)
	if err != nil {
		return nil, err
	}
	certPath, err := url.Parse(mainConfig.Vault.CertPath)
	if err != nil {
		return nil, err
	}
	loginPath, err := url.Parse(mainConfig.Vault.LoginPath)
	if err != nil {
		return nil, err
	}

	return &vault.Client{
		BaseUrl:   *baseUrl,
		CertPath:  *certPath,
		LoginPath: *loginPath,
		RoleId:    mainConfig.Vault.RoleId,
		SecretId:  mainConfig.Vault.SecretId,
	}, nil
}
func initCertRequest(certConfig config.CertConfig) vault.CertRequest {
	certRequest := vault.CertRequest{}

	certRequest.CommonName = certConfig.CommonName
	certRequest.AlternateNames = strings.Join(certConfig.AlternateNames, ",")

	return certRequest
}

func persistCertificate(mainCfg config.MainConfig, certConfig config.CertConfig, cert vault.CertResponse) error {
	var err error

	checkError := func(name string, content string, certConfig config.CertConfig, perm os.FileMode) {
		if err != nil {
			return
		}
		err = saveDownloadedFile(name, content, perm)
	}

	certBaseDir := path.Join(mainCfg.DownloadedCertPath, certConfig.CommonName)

	checkError(path.Join(certBaseDir, certFileName), cert.Data.Certificate, certConfig, 0644)
	checkError(path.Join(certBaseDir, chainFileName), cert.Data.Chain, certConfig, 0644)
	checkError(path.Join(certBaseDir, issuingCAFileName), cert.Data.IssuingCa, certConfig, 0644)
	checkError(path.Join(certBaseDir, privateFileName), cert.Data.PrivateKey, certConfig, 0600)

	if err != nil {
		return err
	}

	err = saveOutputFile(certConfig, cert)
	if err != nil {
		return err
	}
	return nil
}

func saveOutputFile(certConfig config.CertConfig, cert vault.CertResponse) error {
	switch certConfig.Output.File.Type {
	case "bundle":
		return saveBundleFile(certConfig, cert)
	default:
		return fmt.Errorf("Error: ouput.file.type %s not supported. Can only be bundle\n", certConfig.Output.File.Type)
	}
}

func saveBundleFile(certConfig config.CertConfig, cert vault.CertResponse) error {
	log.Printf("Saving output file %s\n", certConfig.Output.File.Name)

	var content string

	for _, v := range certConfig.Output.Items {
		switch v {
		case "certificate":
			content += cert.Data.Certificate + "\n"
		case "privateKey":
			content += cert.Data.PrivateKey + "\n"
		case "issuingCa":
			content += cert.Data.IssuingCa + "\n"
		case "chain":
			content += cert.Data.Chain + "\n"
		default:
			return fmt.Errorf("Error: config output.items is invalid. Valid values are: certificate, privateKey, issuingCa, chain\n")
		}
	}

	path := filepath.Dir(certConfig.Output.File.Name)
	if err := os.MkdirAll(path, certConfig.Output.File.Perm); err != nil {
		return fmt.Errorf("Error: can't create directory %s: %v", path, err)
	}

	if err := ioutil.WriteFile(certConfig.Output.File.Name, []byte(content), certConfig.Output.File.Perm); err != nil {
		return fmt.Errorf("Error: unable to write bundle file %s: %v", certConfig.Output.File.Name, err)
	}

	userId, err := certConfig.UserId()
	if err != nil {
		return err
	}
	groupId, err := certConfig.GroupId()
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(userId)
	if err != nil {
		return fmt.Errorf("Error: cannot convert %s to int:%v\n", userId, err)
	}
	gid, err := strconv.Atoi(groupId)
	if err != nil {
		return fmt.Errorf("Error: cannot convert %s to int:%v\n", groupId, err)
	}

	if err := os.Chown(certConfig.Output.File.Name, uid, gid); err != nil {
		return fmt.Errorf("Error: failed to change file ownership on %s to %d:%d:%v\n", certConfig.Output.File.Name, uid, gid, err)
	}
	return nil
}

func saveDownloadedFile(name string, content string, perm os.FileMode) error {
	log.Printf("Saving certificate file %s\n", name)

	path := filepath.Dir(name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("Error: can't create directory %s: %v", path, err)
	}

	if err := ioutil.WriteFile(name, []byte(content), perm); err != nil {
		return fmt.Errorf("Error: unable to write file %s: %v\n", name, err)
	}
	return nil
}

func isCertificateExpired(certConfig config.CertConfig, mainConfig config.MainConfig) bool {
	certFile := path.Join(mainConfig.DownloadedCertPath, certConfig.CommonName, certFileName)

	if _, err := os.Stat(certConfig.Output.File.Name); err != nil {
		log.Printf("Output certificate file %s does not exist.\n", certConfig.Output.File.Name)
		return true
	}

	if _, err := os.Stat(certFile); err != nil {
		log.Printf("Cached certificate file %s does not exist.\n", certFile)
		return true
	}

	content, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Printf("Error: reading file %s: %v\n", certFile, err)
		return true
	}

	block, _ := pem.Decode([]byte(content))
	if err != nil {
		log.Printf("Error: failed to parse certificate PEM %s: %v\n", certFile, err)
		return true
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Error: failed to parse certificate X509 %s: %v\n", certFile, err)
		return true
	}

	cutoffTime := cert.NotAfter.Add(-24 * time.Hour)

	if time.Now().After(cutoffTime) {
		log.Printf("Certificate expired: %v cert date: %v check date: %v\n", certFile, cert.NotAfter, cutoffTime)
		return true
	}

	return false
}

func restartService(command string) {
	if command == "" {
		log.Printf("No reload command specified. Skipping.\n")
	}

	log.Printf("Executing command `%v'\n", command)
	cmd := exec.Command("/bin/bash", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("Error executing command. error: %v\n", err)
		log.Printf("Output: %q\n", out.String())
	}
}
