package verification

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/digitorus/pdfsign/verify"
)

// applyTrust identifies the actual CMS signer before checking its certificate.
// A second PDF traversal is required by pdfsign v0.9.0's response API.
func applyTrust(file *os.File, response *verify.Response, result *Result, options Options, data scan) error {
	now := time.Now()
	for i := range result.Signatures {
		signature := &result.Signatures[i]
		for _, cert := range response.Signers[i].Certificates {
			if strings.Contains(cert.VerifyError, "not standards compliant") {
				signature.Warnings = append(signature.Warnings, "Diagnóstico X.509 original: "+cert.VerifyError)
			}
		}
		signature.PubliclyTrustedIssuer = response.Signers[i].TrustedIssuer
		signature.TrustedIssuer = false
		signature.TrustScope = "NOT_CHECKED"
		signature.CertificateValidity = "NOT_CHECKED"
		signature.IssuerError = "No se pudo identificar inequívocamente el certificado del firmante CMS."
		if len(data.revisions) != len(result.Signatures) || data.revisions[i].leaf == nil {
			continue
		}
		leaf := data.revisions[i].leaf
		matched := false
		for _, embedded := range response.Signers[i].Certificates {
			if embedded.Certificate != nil && bytes.Equal(leaf.Raw, embedded.Certificate.Raw) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		signature.CertificateValidity = "VALID_NOW"
		if now.Before(leaf.NotBefore) {
			signature.CertificateValidity = "NOT_YET_VALID"
		} else if now.After(leaf.NotAfter) {
			signature.CertificateValidity = "EXPIRED"
		}
		if options.Roots == nil {
			signature.IssuerError = "No se configuraron raíces de confianza."
			continue
		}
		intermediates := x509.NewCertPool()
		if options.Intermediates != nil {
			intermediates = options.Intermediates.Clone()
		}
		for _, embedded := range response.Signers[i].Certificates {
			if embedded.Certificate != nil && embedded.Certificate.IsCA {
				intermediates.AddCert(embedded.Certificate)
			}
		}
		signature.TrustScope = "CONFIGURED_ROOTS"
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots: options.Roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth},
		})
		if err == nil && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			err = fmt.Errorf("certificado sin uso DigitalSignature")
		}
		if err != nil {
			signature.IssuerError = err.Error()
		} else {
			signature.TrustedIssuer = true
			signature.IssuerError = ""
			if len(chains) > 0 && len(chains[0]) > 1 {
				for _, embedded := range response.Signers[i].Certificates {
					if embedded.Certificate != nil && bytes.Equal(leaf.Raw, embedded.Certificate.Raw) {
						applyOCSP(signature, leaf, chains[0][1], embedded)
						break
					}
				}
			}
		}
		// Verify does not consult OCSP or CRLs: preserve the independent revocation state.
	}
	return nil
}
