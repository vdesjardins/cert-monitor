package vault

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

type mockTransport struct{}

func (t *mockTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/certs":
		return t.handleCertRequest(request)
	case "/certs/404":
		return t.handleCertRequest404(request)
	case "/certs/name-invalid":
		return t.handleNameInvalid(request)
	case "/login":
		return t.handleRefreshToken(request)
	default:
		return nil, fmt.Errorf("Unknown request %v", request.URL.Path)
	}
}

func (t *mockTransport) handleCertRequest404(request *http.Request) (*http.Response, error) {
	content := []byte("")

	response := http.Response{}
	response.Body = ioutil.NopCloser(bytes.NewReader(content))
	response.StatusCode = 404
	return &response, nil
}

func (t *mockTransport) handleCertRequest(request *http.Request) (*http.Response, error) {
	return readTestData("new_cert.json", request)
}

func (t *mockTransport) handleRefreshToken(request *http.Request) (*http.Response, error) {
	return readTestData("login.json", request)
}

func (t *mockTransport) handleNameInvalid(request *http.Request) (*http.Response, error) {
	response, err := readTestData("name_invalid.json", request)
	response.StatusCode = 400
	return response, err
}

func readTestData(testName string, request *http.Request) (*http.Response, error) {
	content, err := ioutil.ReadFile(filepath.Join("testdata", testName))
	if err != nil {
		return nil, err
	}

	response := http.Response{}
	response.Body = ioutil.NopCloser(bytes.NewReader(content))
	response.StatusCode = 200
	return &response, nil
}

func TestRefreshToken(t *testing.T) {
	savedDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: &mockTransport{}}

	baseUrl, _ := url.Parse("http://127.0.0.1/")
	loginPath, _ := url.Parse("/login")
	certPath, _ := url.Parse("/certs")

	client := Client{
		BaseUrl:   *baseUrl,
		LoginPath: *loginPath,
		CertPath:  *certPath,
		RoleId:    "role",
		SecretId:  "secret",
	}

	authToken, err := client.refreshToken()
	if err != nil {
		t.Errorf("Error %v", err)
	}
	if authToken != "98a4c7ab-b1fe-361b-ba0b-e307aacfd587" {
		t.Errorf("Expected '98a4c7ab-b1fe-361b-ba0b-e307aacfd587', got %v", authToken)
	}

	http.DefaultClient = savedDefaultClient
}

func TestFetchNewCertificate(t *testing.T) {
	requestCertificate("/certs", func(err error) {
		if err != nil {
			t.Errorf("Error %v", err)
		}
	})

	requestCertificate("/certs/404", func(err error) {
		if err == nil {
			t.Errorf("Error status code 404 is supposed the be an error")
		}
	})

	requestCertificate("/certs/name-invalid", func(err error) {
		if err == nil {
			t.Errorf("Error status code 400 is supposed the be an error")
		}
		if err != nil {
			if strings.Contains(err.Error(), "errors:") == false {
				t.Errorf("Error error should contain context message")
			}
		}
	})
}

func requestCertificate(testUrl string, assertion func(err error)) {
	savedDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: &mockTransport{}}

	baseUrl, _ := url.Parse("http://127.0.0.1/")
	loginPath, _ := url.Parse("/login")
	certPath, _ := url.Parse(testUrl)

	config := Client{
		BaseUrl:   *baseUrl,
		LoginPath: *loginPath,
		CertPath:  *certPath,
		RoleId:    "role",
		SecretId:  "secret",
	}
	certReq := CertRequest{
		CommonName:     "test.domain.com",
		AlternateNames: "test-2.domain.com,test-3.domain.com",
	}
	vaultToken := "dummy token"

	_, err := config.fetchNewCertificate(certReq, vaultToken)
	assertion(err)

	http.DefaultClient = savedDefaultClient
}
