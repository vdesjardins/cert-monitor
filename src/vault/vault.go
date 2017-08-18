package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type CertResponse struct {
	Data struct {
		Chain       string `json:"chain"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
		IssuingCa   string `json:"issuing_ca"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type CertRequest struct {
	CommonName     string `json:"common_name"`
	AlternateNames string `json:"alt_names"`
}

type Config struct {
	BaseUrl   string
	LoginPath string
	CertPath  string
	RoleId    string
	SecretId  string
}

type loginRequest struct {
	RoleId   string `json:"role_id"`
	SecretId string `json:"secret_id"`
}

type loginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

func (config Config) refreshToken() (string, error) {
	var message loginResponse
	var token string

	loginInfo := loginRequest{config.RoleId, config.SecretId}

	loginPayload, err := json.Marshal(loginInfo)
	if err != nil {
		return token, err
	}

	loginPayloadReader := bytes.NewReader(loginPayload)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, config.BaseUrl+config.LoginPath, loginPayloadReader)
	if err != nil {
		return token, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return token, err
	}
	if err := json.Unmarshal(body, &message); err != nil {
		return token, err
	}

	if resp.StatusCode != 200 {
		return token, fmt.Errorf("Error: vault auth status: %d errors: %v", resp.StatusCode, message.Errors)
	}

	return message.Auth.ClientToken, nil
}

func (config Config) FetchNewCertificate(certReq CertRequest) (CertResponse, error) {
	var message CertResponse

	vaultToken, err := config.refreshToken()
	if err != nil {
		return message, err
	}

	certPayload, err := json.Marshal(certReq)
	if err != nil {
		return message, err
	}

	certPayloadReader := bytes.NewReader(certPayload)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, config.BaseUrl+config.CertPath, certPayloadReader)
	if err != nil {
		return message, err
	}

	req.Header.Add("X-Vault-Token", vaultToken)

	resp, err := client.Do(req)
	if err != nil {
		return message, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return message, err
	}
	if err := json.Unmarshal(body, &message); err != nil {
		return message, err
	}

	if resp.StatusCode != 200 {
		return message, fmt.Errorf("Error: vault status: %d errors: %v", resp.StatusCode, message.Errors)
	}

	return message, nil
}

// func (cert CertResponse) getExpirationDate() date
