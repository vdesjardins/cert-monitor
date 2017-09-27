package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func (client Client) refreshToken() (string, error) {
	loginInfo := loginRequest{client.RoleId, client.SecretId}

	loginPayload, err := json.Marshal(loginInfo)
	if err != nil {
		return "", fmt.Errorf("Error marshalling Vault request: %v", err)
	}

	loginPayloadReader := bytes.NewReader(loginPayload)
	url := client.BaseUrl.ResolveReference(&client.LoginPath).String()
	req, err := http.NewRequest(http.MethodPost, url, loginPayloadReader)
	if err != nil {
		return "", fmt.Errorf("Error creating Vault request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error calling Vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errors := ""
		message, err := client.readJSONResponse(resp.Body)
		if err == nil {
			errors = fmt.Sprintf("errors: %v", message.Errors)
		}

		return "", fmt.Errorf("Error: vault auth status: %d %v", resp.StatusCode, errors)
	}

	message, err := client.readJSONResponse(resp.Body)
	if err != nil {
		return "", err
	}

	return message.Auth.ClientToken, nil
}

func (client Client) readJSONResponse(body io.ReadCloser) (loginResponse, error) {
	var message loginResponse

	b, err := ioutil.ReadAll(body)
	if err != nil {
		return message, fmt.Errorf("Error reading Vault response: %v", err)
	}

	if err := json.Unmarshal(b, &message); err != nil {
		return message, fmt.Errorf("Error unmarshalling Vault response: %v", err)
	}

	return message, nil
}

func (client Client) FetchNewCertificate(certReq CertRequest) (CertResponse, error) {
	var message CertResponse

	vaultToken, err := client.refreshToken()
	if err != nil {
		return message, fmt.Errorf("Error refreshing Vault token: %v", err)
	}

	return client.fetchNewCertificate(certReq, vaultToken)
}

func (client Client) fetchNewCertificate(certReq CertRequest, vaultToken string) (CertResponse, error) {
	var message CertResponse

	certPayload, err := json.Marshal(certReq)
	if err != nil {
		return message, fmt.Errorf("Error marshalling Vault request: %v", err)
	}

	certPayloadReader := bytes.NewReader(certPayload)
	url := client.BaseUrl.ResolveReference(&client.CertPath).String()

	req, err := http.NewRequest(http.MethodPost, url, certPayloadReader)
	if err != nil {
		return message, fmt.Errorf("Error creating request: %v", err)
	}

	req.Header.Add("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return message, fmt.Errorf("Error calling Vault: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return message, fmt.Errorf("Error reading Vault response: %v", err)
	}
	if err := json.Unmarshal(body, &message); err != nil {
		return message, fmt.Errorf("Error unmarshalling Vault response: %v", err)
	}

	if resp.StatusCode != 200 {
		return message, fmt.Errorf("Error: vault status: %d errors: %v", resp.StatusCode, message.Errors)
	}

	return message, nil
}

// func (cert CertResponse) getExpirationDate() date
