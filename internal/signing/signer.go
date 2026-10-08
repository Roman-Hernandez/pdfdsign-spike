package signing

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
	"pdfsing_test/internal/verification"
)

type Options struct {
	CertificateChains [][]*x509.Certificate
	Name              string
	Location          string
	Reason            string
	Contact           string
	CertType          sign.CertType
	DocMDPPerm        sign.DocMDPPerm
	Appearance        sign.Appearance
	TSAURL            string
}

// Sign applies a cryptographic signature to the input PDF and saves it to output.
func Sign(input, output string, cert *x509.Certificate, signer crypto.Signer, opts Options) error {
	if cert == nil || signer == nil {
		return fmt.Errorf("certificate and signer are required")
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("certificate does not match signing key")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is outside its validity period")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate does not permit digital signatures")
	}
	inPath, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	outPath, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if inPath == outPath {
		return fmt.Errorf("input and output must differ")
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	// Fallback to ApprovalSignature if not specified
	if opts.CertType == 0 {
		opts.CertType = sign.ApprovalSignature
	}

	if opts.CertType != sign.ApprovalSignature && opts.CertType != sign.CertificationSignature {
		return fmt.Errorf("only approval and certification signatures are supported")
	}
	if opts.CertType == sign.CertificationSignature {
		if opts.DocMDPPerm == 0 {
			opts.DocMDPPerm = sign.DoNotAllowAnyChangesPerms
		}
		if opts.DocMDPPerm < 1 || opts.DocMDPPerm > 3 {
			return fmt.Errorf("DocMDP permission must be 1, 2 or 3")
		}
	} else if opts.DocMDPPerm != 0 {
		return fmt.Errorf("DocMDP only applies to certification")
	}
	count, permission, restricted, err := verification.SigningPolicy(input)
	if err != nil {
		return err
	}
	if opts.CertType == sign.CertificationSignature && count > 0 {
		return fmt.Errorf("certification must be the first signature")
	}
	if restricted {
		return fmt.Errorf("unsupported signature filter or FieldMDP restrictions; cannot safely append")
	}
	if permission != 0 {
		return fmt.Errorf("existing DocMDP certification (P=%d): this spike cannot establish that adding a new field is permitted", permission)
	}
	if count > 0 {
		previous, err := verification.Verify(input)
		if err != nil {
			return err
		}
		if previous.Status != verification.StatusValid || len(previous.Signatures) != count {
			return fmt.Errorf("previous signatures/revisions must verify before appending")
		}
	}
	signData := sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        opts.Name,
				Location:    opts.Location,
				Reason:      opts.Reason,
				ContactInfo: opts.Contact,
				Date:        time.Now(),
			},
			CertType:   opts.CertType,
			DocMDPPerm: opts.DocMDPPerm,
		},
		Signer:            signer,
		Certificate:       cert,
		CertificateChains: opts.CertificateChains,
		DigestAlgorithm:   crypto.SHA256,
		// Spike offline: OCSP/CRL embedding needs a separate controlled evaluation.
		RevocationFunction: func(_ *x509.Certificate, _ *x509.Certificate, _ *revocation.InfoArchival) error { return nil },
		Appearance:         opts.Appearance,
	}

	if opts.TSAURL != "" {
		signData.TSA = sign.TSA{
			URL: opts.TSAURL,
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(output), ".pdfsign-*.pdf")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	defer os.Remove(tmpPath)
	err = sign.SignFile(input, tmpPath, signData)
	if err != nil {
		return fmt.Errorf("error signing PDF: %w", err)
	}

	if count > 0 {
		preserved, err := verification.PreservesOriginal(input, tmpPath)
		if err != nil {
			return err
		}
		if !preserved {
			return fmt.Errorf("library rewrote previous PDF bytes; result not published")
		}
	}
	checked, err := verification.Verify(tmpPath)
	if err != nil {
		return err
	}
	if checked.Status != verification.StatusValid || len(checked.Signatures) != count+1 {
		return fmt.Errorf("new or previous signatures failed verification; result not published")
	}
	// Link publishes the completed file without overwriting an existing output.
	return os.Link(tmpPath, output)
}
