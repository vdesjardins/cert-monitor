package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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

type Client struct {
	BaseUrl   url.URL
	LoginPath url.URL
	CertPath  url.URL
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

func (client Client) refreshToken() (string, error) {
	var message loginResponse
	var token string

	loginInfo := loginRequest{client.RoleId, client.SecretId}

	loginPayload, err := json.Marshal(loginInfo)
	if err != nil {
		return token, err
	}

	loginPayloadReader := bytes.NewReader(loginPayload)
	url := client.BaseUrl.ResolveReference(&client.LoginPath).String()
	req, err := http.NewRequest(http.MethodPost, url, loginPayloadReader)
	if err != nil {
		return token, err
	}

	resp, err := http.DefaultClient.Do(req)
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

func (client Client) FetchNewCertificate(certReq CertRequest) (CertResponse, error) {
	var message CertResponse

	vaultToken, err := client.refreshToken()
	if err != nil {
		return message, err
	}

	return client.fetchNewCertificate(certReq, vaultToken)
}
func (client Client) fetchNewCertificate(certReq CertRequest, vaultToken string) (CertResponse, error) {
	var message CertResponse

	certPayload, err := json.Marshal(certReq)
	if err != nil {
		return message, err
	}

	certPayloadReader := bytes.NewReader(certPayload)
	url := client.BaseUrl.ResolveReference(&client.CertPath).String()
	req, err := http.NewRequest(http.MethodPost, url, certPayloadReader)
	if err != nil {
		return message, err
	}

	req.Header.Add("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
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
