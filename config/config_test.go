package config

import (
	"testing"
	"time"
)

type testTtl struct {
	ttl      time.Duration
	renewTtl time.Duration
}

var testDataTtls = [][]testTtl{
	// must fail
	[]testTtl{
		{0, 0},
		{1, 0},
		{0, 1},
		{1, 1}},
	// must succeed
	[]testTtl{
		{2, 1}},
}

func TestValidateTTL(t *testing.T) {
	for setIdx, ttlTests := range testDataTtls {
		for k, v := range ttlTests {
			cert := CertConfig{
				TTL:      v.ttl,
				RenewTTL: v.renewTtl,
			}

			if setIdx == 0 {
				if err := cert.validateTTL(); err == nil {
					t.Errorf("test %v should have failed. Value %v", k, v)
				}
			} else {
				if err := cert.validateTTL(); err != nil {
					t.Errorf("test %v should have succeeded. Value %v", k, v)
				}
			}

		}
	}
}

func TestValidateCommonName(t *testing.T) {
	cert := CertConfig{CommonName: ""}

	if err := cert.validateCommonName(); err == nil {
		t.Errorf("CommonName validation must failed if not set")
	}

	cert.CommonName = "test.domain.tld"
	if err := cert.validateCommonName(); err != nil {
		t.Errorf("CommonName validation should succeed if set")
	}
}

func TestValidate(t *testing.T) {
	cert := CertConfig{CommonName: "test.domain.tld", TTL: 2, RenewTTL: 1}
	if err := cert.Validate(); err != nil {
		t.Errorf("Cannot validate certificate configuration: %v", cert)
	}

}
