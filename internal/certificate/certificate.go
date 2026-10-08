package certificate

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCertificate reads an X.509 certificate from a PEM file.
func LoadCertificate(path string) (*x509.Certificate, error) {
	certificates, err := LoadCertificates(path)
	if err != nil {
		return nil, err
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("expected one signing certificate in %s", path)
	}
	return certificates[0], nil
}

// LoadPrivateKey reads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("error inspecting private key: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key permissions must exclude group/others; use chmod 600")
	}
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading private key %s: %w", path, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("could not decode PEM from %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if pkcs1Err != nil {
			return nil, fmt.Errorf("could not parse private key as PKCS#8 or PKCS#1: %w", err)
		}
		key = rsaKey
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return privateKey, nil
}

// LoadCertificates reads every certificate in a PEM bundle. An empty path is optional.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("certificate PEM file is empty: %s", path)
	}
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid certificate PEM in %s", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
		data = rest
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return certificates, nil
}

// LoadPool creates an explicit trust/candidate pool, never modifies system roots.
func LoadPool(path string) (*x509.CertPool, error) {
	certificates, err := LoadCertificates(path)
	if err != nil || path == "" {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certificates {
		pool.AddCert(cert)
	}
	return pool, nil
}
