package main_test

import (
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdfsign/sign"
	"pdfsing_test/internal/certificate"
	"pdfsing_test/internal/signing"
	"pdfsing_test/internal/verification"
)

// Integration scenarios use existing evaluation resources only by explicit request.
func setupKeysAndCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if os.Getenv("PDFSIGN_INTEGRATION") != "1" {
		t.Skip("set PDFSIGN_INTEGRATION=1 to use local evaluation inputs")
	}
	if os.Getenv("PDFSIGN_CERT") == "" || os.Getenv("PDFSIGN_KEY") == "" || os.Getenv("PDFSIGN_INPUT") == "" {
		t.Skip("set PDFSIGN_CERT, PDFSIGN_KEY and PDFSIGN_INPUT to existing evaluation resources")
	}
	cert, err := certificate.LoadCertificate(os.Getenv("PDFSIGN_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := certificate.LoadPrivateKey(os.Getenv("PDFSIGN_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestSignAndVerifyPDF(t *testing.T) {
	cert, key := setupKeysAndCert(t)
	out := filepath.Join(t.TempDir(), "signed.pdf")
	if err := signing.Sign(os.Getenv("PDFSIGN_INPUT"), out, cert, key, signing.Options{Name: "Tester", CertType: sign.ApprovalSignature}); err != nil {
		t.Fatal(err)
	}
	res, err := verification.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Signatures) != 1 || !res.Signatures[0].Valid {
		t.Fatalf("expected one valid signature: %+v", res)
	}
}

func TestMultipleSignatures(t *testing.T) {
	cert, key := setupKeysAndCert(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "first.pdf")
	second := filepath.Join(dir, "second.pdf")
	for _, paths := range [][2]string{{os.Getenv("PDFSIGN_INPUT"), first}, {first, second}} {
		if err := signing.Sign(paths[0], paths[1], cert, key, signing.Options{CertType: sign.ApprovalSignature}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := verification.Verify(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Signatures) != 2 {
		t.Fatalf("expected two signatures: %+v", res)
	}
}

func TestCertificationSignature(t *testing.T) {
	cert, key := setupKeysAndCert(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "certified.pdf")
	second := filepath.Join(dir, "approved.pdf")
	if err := signing.Sign(os.Getenv("PDFSIGN_INPUT"), first, cert, key, signing.Options{CertType: sign.CertificationSignature, DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms}); err != nil {
		t.Fatal(err)
	}
	if err := signing.Sign(first, second, cert, key, signing.Options{CertType: sign.ApprovalSignature}); err == nil {
		t.Fatal("expected conservative rejection of appending to a DocMDP-certified PDF")
	}
}

func TestTSA(t *testing.T) {
	cert, key := setupKeysAndCert(t)
	url := os.Getenv("PDFSIGN_TSA_URL")
	if url == "" {
		t.Skip("set PDFSIGN_TSA_URL to a controlled TSA")
	}
	out := filepath.Join(t.TempDir(), "tsa.pdf")
	if err := signing.Sign(os.Getenv("PDFSIGN_INPUT"), out, cert, key, signing.Options{TSAURL: url}); err != nil {
		t.Fatal(err)
	}
	res, err := verification.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Signatures) != 1 || !res.Signatures[0].TimestampValid {
		t.Fatalf("missing valid timestamp: %+v", res)
	}
}
