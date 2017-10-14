package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type CertResponse struct {
	Data struct {
		Chain       []string `json:"ca_chain"`
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"private_key"`
		IssuingCa   string   `json:"issuing_ca"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type CertRequest struct {
	CommonName     string `json:"common_name"`
	AlternateNames string `json:"alt_names"`
	TTL            string `json:"ttl,omitempty"`
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

func (client Client) FetchNewCertificate(certReq CertRequest) (CertResponse, error) {
	var message CertResponse

	vaultToken, err := client.refreshToken()
	if err != nil {
		return message, fmt.Errorf("Error refreshing Vault token: %v", err)
	}

	return client.fetchNewCertificate(certReq, vaultToken)
}

func (client Client) refreshToken() (string, error) {
	loginInfo := loginRequest{client.RoleId, client.SecretId}

	loginPayload := &bytes.Buffer{}
	err := json.NewEncoder(loginPayload).Encode(loginInfo)
	if err != nil {
		return "", fmt.Errorf("Error marshalling Vault request: %v", err)
	}

	url := client.BaseUrl.ResolveReference(&client.LoginPath).String()
	req, err := http.NewRequest(http.MethodPost, url, loginPayload)
	if err != nil {
		return "", fmt.Errorf("Error creating Vault request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error calling Vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var message loginResponse
		errors := ""
		err := json.NewDecoder(resp.Body).Decode(&message)
		if err == nil {
			errors = fmt.Sprintf("errors: %v", message.Errors)
		}

		return "", fmt.Errorf("Error: vault auth status: %d %v", resp.StatusCode, errors)
	}

	var message loginResponse
	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {
		return "", err
	}

	return message.Auth.ClientToken, nil
}

func (client Client) fetchNewCertificate(certReq CertRequest, vaultToken string) (CertResponse, error) {
	var message CertResponse

	certPayload := &bytes.Buffer{}
	err := json.NewEncoder(certPayload).Encode(certReq)
	if err != nil {
		return message, fmt.Errorf("Fetch certificate: Error marshalling Vault request: %v", err)
	}

	url := client.BaseUrl.ResolveReference(&client.CertPath).String()

	req, err := http.NewRequest(http.MethodPost, url, certPayload)
	if err != nil {
		return message, fmt.Errorf("Fetch certificate: Error creating request: %v", err)
	}

	req.Header.Add("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return message, fmt.Errorf("Fetch certificate: Error calling Vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err := json.NewDecoder(resp.Body).Decode(&message)
		if err != nil {
			return message, fmt.Errorf("Fetch certificate: Error: vault status: %d errors: %v", resp.StatusCode, message.Errors)
		}
		return message, fmt.Errorf("Fetch certificate: Error: vault status: %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {
		return message, fmt.Errorf("Fetch certificate: Error reading Vault response: %v", err)
	}

	return message, nil
}
