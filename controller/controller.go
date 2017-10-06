package controller

import (
	"bytes"
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
	"text/tabwriter"
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
	log.Printf("Main configuration '%s' loaded sucessefully.\n", configPath)

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
		log.Printf("Main configuration '%s' loaded sucessefully.\n", configPath)

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
				if err != nil {
					log.Printf("%v\n", err)
					continue
				}
				log.Printf("Main configuration '%s' loaded sucessefully.\n", configPath)
				execute(cfg, noReload, false, "")
			}

		}
	}()

	wg.Wait()
}

func PrintStatus(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Printf("%v", err)
		return err
	}

	files, err := cfg.ResolveConfigDirs()
	if err != nil {
		log.Printf("%v", err)
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	fmt.Fprintln(w, "Configuration\tTTL\tRenewTTL\tNot Before\tRenew After\tNot After")
	format := "%v\t%v\t%v\t%v\t%v\t%v\n"

	for _, v := range files {
		c, err := cfg.LoadCertConfig(v)
		if err != nil {
			fmt.Fprintf(w, format, v, "-", "-", "-", "-", "-")
			continue
		}

		cert, err := c.LoadCachedCertificate()
		if err != nil {
			fmt.Fprintf(w, format, v, c.TTL, c.RenewTTL, "-", "-", "-")
			continue
		}
		fmt.Fprintf(w, format, v, c.TTL, c.RenewTTL,
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Add(-c.RenewTTL).Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339))
	}

	w.Flush()

	return nil
}

func loadConfig(configPath string) (*config.MainConfig, error) {
	cfg, err := config.LoadMainConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("Error loading main configuration: %v", err)
	}

	return cfg, nil
}

func execute(cfg *config.MainConfig, noReload bool, failOnError bool, certConfigPath string) error {
	if certConfigPath != "" {
		return checkCertificatesAndRenew(cfg, []string{certConfigPath}, noReload, failOnError)
	}

	files, err := cfg.ResolveConfigDirs()
	if err != nil {
		fmt.Println(err)
		if failOnError == true {
			return err
		}
	}

	return checkCertificatesAndRenew(cfg, files, noReload, failOnError)
}

func checkCertificatesAndRenew(cfg *config.MainConfig, files []string, noReload, failOnError bool) error {
	vaultCfg, err := initVaultClient(*cfg)
	if err != nil {
		log.Printf("%+v\n", err)
		return err
	}

	servicesToRestart := map[string]bool{}

	for _, f := range files {
		certConfig, err := cfg.LoadCertConfig(f)
		if err != nil {
			log.Println(err)
			if failOnError == true {
				return err
			}
			continue
		}

		certReq := initCertRequest(certConfig)

		if !certConfig.IsExpired() {
			continue
		}

		log.Printf("Generating certificate for commonName %v alternateNames %v", certConfig.CommonName, certConfig.AlternateNames)
		cert, err := vaultCfg.FetchNewCertificate(certReq)
		if err != nil {
			log.Printf("%v", err)
			if failOnError == true {
				return err
			}
			continue
		}

		if err := persistCertificate(*cfg, certConfig, cert); err != nil {
			log.Printf("Error saving new certificate: %v", err)
			if failOnError == true {
				return err
			}
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
	if certConfig.TTL != 0 {
		certRequest.TTL = certConfig.TTL.String()
	}

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

	appendContent := func(str string) {
		if str != "" {
			content += str + "\n"
		}
	}
	for _, v := range certConfig.Output.Items {
		switch v {
		case "certificate":
			appendContent(cert.Data.Certificate)
		case "privateKey":
			appendContent(cert.Data.PrivateKey)
		case "issuingCa":
			appendContent(cert.Data.IssuingCa)
		case "chain":
			appendContent(cert.Data.Chain)
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
