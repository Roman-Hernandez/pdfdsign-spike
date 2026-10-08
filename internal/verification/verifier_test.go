package verification

import (
	"errors"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/verify"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

func TestClassifyUnsigned(t *testing.T) {
	err := errors.New("error verifying file: no digital signature in document")
	res := ClassifyVerificationResult(nil, err)

	if res.Status != StatusUnsigned {
		t.Errorf("expected StatusUnsigned, got %s", res.Status)
	}
}

func TestClassifyCorrupted(t *testing.T) {
	err := errors.New("error verifying file: invalid format")
	res := ClassifyVerificationResult(nil, err)

	if res.Status != StatusVerificationError {
		t.Errorf("expected StatusVerificationError, got %s", res.Status)
	}
}

func TestClassifyInvalidCrypto(t *testing.T) {
	now := time.Now()
	resp := &verify.Response{
		Error: "Message digest mismatch",
		Signers: []verify.Signer{
			{
				Name:           "Test Signer",
				ValidSignature: false,
				TrustedIssuer:  false,
				SignatureTime:  &now,
			},
		},
	}
	res := ClassifyVerificationResult(resp, nil)

	if res.Status != StatusInvalidSignature {
		t.Errorf("expected StatusInvalidSignature, got %s", res.Status)
	}

	if len(res.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(res.Signatures))
	}
	if res.Signatures[0].Valid {
		t.Errorf("expected Valid to be false")
	}
}

func TestClassifyValidTSA(t *testing.T) {
	now := time.Now()
	resp := &verify.Response{
		Signers: []verify.Signer{
			{
				Name:             "Test Signer",
				ValidSignature:   true,
				TrustedIssuer:    true,
				SignatureTime:    &now,
				TimeStamp:        &timestamp.Timestamp{Time: now},
				TimestampStatus:  "valid",
				TimestampTrusted: true,
			},
		},
	}
	res := ClassifyVerificationResult(resp, nil)

	if res.Status != StatusValid {
		t.Errorf("expected StatusValid, got %s", res.Status)
	}
	if len(res.Signatures) != 1 {
		t.Fatalf("expected 1 signature")
	}
	sig := res.Signatures[0]
	if !sig.TimestampPresent || !sig.TimestampValid || sig.TimestampTrust != "trusted" || !sig.TimestampTime.Equal(now) {
		t.Fatalf("timestamp mapping failed: %+v", sig)
	}
	if !sig.Valid {
		t.Errorf("expected valid signature")
	}
	if sig.Revocation != RevocationNotChecked {
		t.Errorf("expected RevocationNotChecked, got %s", sig.Revocation)
	}
}

func TestClassifyMissingResponse(t *testing.T) {
	if res := ClassifyVerificationResult(nil, nil); res.Status != StatusVerificationError {
		t.Fatalf("nil response: %+v", res)
	}
	res := ClassifyVerificationResult(&verify.Response{Error: "parse failure"}, nil)
	if res.Status == StatusUnsigned {
		t.Fatal("verification failure must not become unsigned")
	}
}

func TestRevocationUnknownIsNotGood(t *testing.T) {
	res := ClassifyVerificationResult(&verify.Response{Signers: []verify.Signer{{ValidSignature: true, Certificates: []verify.Certificate{{OCSPEmbedded: true, OCSPResponse: &ocsp.Response{Status: ocsp.Unknown}}}}}}, nil)
	if res.Signatures[0].Revocation != RevocationUnknown {
		t.Fatalf("unknown OCSP misclassified: %+v", res.Signatures[0])
	}
}
