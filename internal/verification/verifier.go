package verification

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/digitorus/pdfsign/verify"
)

type DocumentStatus string

const (
	StatusValid             DocumentStatus = "DOCUMENTO ÍNTEGRO"
	StatusModified          DocumentStatus = "MODIFICACIONES POSTERIORES A LA ÚLTIMA FIRMA"
	StatusUnsigned          DocumentStatus = "SIN FIRMA DIGITAL"
	StatusInvalidSignature  DocumentStatus = "FIRMA CRIPTOGRÁFICAMENTE INVÁLIDA"
	StatusVerificationError DocumentStatus = "ERROR DE VERIFICACIÓN"
)

type RevocationStatus string

const (
	RevocationGood       RevocationStatus = "GOOD"
	RevocationRevoked    RevocationStatus = "REVOKED"
	RevocationNotChecked RevocationStatus = "NOT_CHECKED"
	RevocationUnknown    RevocationStatus = "UNKNOWN"
)

type CertInfo struct {
	Subject          string
	Issuer           string
	Serial           string
	NotBefore        time.Time
	NotAfter         time.Time
	KeyUsageValid    bool
	KeyUsageError    string
	ExtKeyUsageValid bool
	ExtKeyUsageError string
	VerifyErr        string
}

type SignatureResult struct {
	Valid                 bool
	SignerName            string
	Reason                string
	Contact               string
	Location              string
	SignedAt              *time.Time
	TrustedIssuer         bool // Trust in explicitly configured roots only.
	PubliclyTrustedIssuer bool
	TrustScope            string
	CertificateValidity   string
	SignedRevisionEnd     int64
	LaterRevision         bool
	Warnings              []string
	IssuerError           string
	Revocation            RevocationStatus
	RevocationReason      string

	TimestampPresent bool
	TimestampValid   bool
	TimestampTime    *time.Time
	TimestampTrust   string

	TimeSource   string
	TimeWarnings []string
	Certificates []CertInfo
}

type Result struct {
	Status       DocumentStatus
	StatusDetail string
	Error        string
	Signatures   []SignatureResult
}

// Verify inspects a PDF for signatures and returns structured results.
func Verify(path string) (*Result, error) {
	return VerifyWithOptions(path, Options{})
}

// Options supplies explicit trust pools and optional network checks.
type Options struct {
	External      bool
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

// VerifyWithOptions never treats embedded certificates as trust anchors.
func VerifyWithOptions(path string, options Options) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return &Result{
			Status:       StatusVerificationError,
			StatusDetail: fmt.Sprintf("no se pudo abrir el archivo: %v", err),
		}, err
	}
	defer f.Close()

	data, scanErr := scanRevisions(f)
	if scanErr != nil {
		return nil, scanErr
	}
	opts := verify.DefaultVerifyOptions()
	opts.EnableExternalRevocationCheck = options.External

	resp, err := verify.VerifyFileWithOptions(f, opts)
	result := ClassifyVerificationResult(resp, err)
	if len(data.revisions) > 0 && (resp == nil || len(resp.Signers) != len(data.revisions)) {
		result.Status = StatusVerificationError
		result.StatusDetail = "Hay estructuras de firma que pdfsign no pudo verificar; no se clasifican como firma ausente."
		return result, nil
	}
	if err != nil || resp == nil || len(resp.Signers) == 0 {
		return result, nil
	}
	var latestEnd int64
	for i, item := range data.revisions {
		s := &result.Signatures[i]
		s.SignedRevisionEnd = item.end
		s.LaterRevision = item.validRange && item.end < data.size
		if !item.validRange {
			s.Valid = false
			result.Status = StatusInvalidSignature
			s.Warnings = append(s.Warnings, "ByteRange inválido o fuera del archivo.")
		}
		if item.end > latestEnd {
			latestEnd = item.end
		}
	}
	if result.Status == StatusValid && latestEnd < data.size {
		result.Status = StatusModified
		result.StatusDetail = "Existen bytes posteriores a la última revisión firmada; no implica por sí solo alteración maliciosa ni cumplimiento DocMDP."
	}
	if err := applyTrust(f, resp, result, options, data); err != nil {
		return result, err
	}
	return result, nil
}

// ClassifyVerificationResult converts the raw pdfsign response into our structured Result.
func ClassifyVerificationResult(resp *verify.Response, err error) *Result {
	if err != nil {
		if strings.Contains(err.Error(), "no digital signature in document") {
			return &Result{
				Status:       StatusUnsigned,
				StatusDetail: "El documento actual no contiene una firma digital verificable.",
			}
		}
		// If it's another error, it's a verification or corrupted error
		return &Result{
			Status:       StatusVerificationError,
			StatusDetail: err.Error(),
		}
	}

	if resp == nil {
		return &Result{Status: StatusVerificationError, StatusDetail: "Respuesta de verificación vacía."}
	}

	result := &Result{
		Status:     StatusValid, // Default to valid, we might change this
		Signatures: make([]SignatureResult, 0, len(resp.Signers)),
	}

	if resp.Error != "" {
		result.Error = resp.Error
		// pdfsign also reports chain/TSA errors here. Only ValidSignature
		// determines cryptographic integrity below.
		result.StatusDetail = resp.Error

	}

	for _, s := range resp.Signers {
		revStatus := RevocationNotChecked
		revReason := "No hay evidencia de revocación validada."
		for _, c := range s.Certificates {
			if c.OCSPResponse != nil || c.OCSPEmbedded || c.OCSPExternal || c.CRLEmbedded || c.CRLExternal {
				revStatus = RevocationUnknown
				revReason = "Hay datos OCSP/CRL, pero su presencia no acredita estado ni autenticidad."
			}
		}
		if s.RevokedCertificate {
			revStatus = RevocationUnknown
			revReason = "pdfsign reportó revocación; requiere confirmar respuesta, emisor y tiempo."
		}

		sigRes := SignatureResult{
			Valid:                 s.ValidSignature,
			SignerName:            s.Name,
			Reason:                s.Reason,
			Location:              s.Location,
			Contact:               s.ContactInfo,
			SignedAt:              s.SignatureTime,
			TimeSource:            s.TimeSource,
			TimeWarnings:          s.TimeWarnings,
			PubliclyTrustedIssuer: s.TrustedIssuer,
			TrustScope:            "NOT_CHECKED",
			CertificateValidity:   "NOT_CHECKED",
			Revocation:            revStatus,
			RevocationReason:      revReason,
			TimestampPresent:      false,
		}

		if !s.ValidSignature {
			result.Status = StatusInvalidSignature
			result.StatusDetail = "La verificación criptográfica de la firma falló."
		}

		if len(s.Certificates) > 0 {
			sigRes.IssuerError = s.Certificates[0].VerifyError
			for _, c := range s.Certificates {
				if c.Certificate != nil {
					sigRes.Certificates = append(sigRes.Certificates, CertInfo{
						Subject:       c.Certificate.Subject.CommonName,
						Issuer:        c.Certificate.Issuer.CommonName,
						Serial:        c.Certificate.SerialNumber.String(),
						NotBefore:     c.Certificate.NotBefore,
						NotAfter:      c.Certificate.NotAfter,
						VerifyErr:     c.VerifyError,
						KeyUsageValid: c.KeyUsageValid, KeyUsageError: c.KeyUsageError, ExtKeyUsageValid: c.ExtKeyUsageValid, ExtKeyUsageError: c.ExtKeyUsageError,
					})
				}
			}
		}

		if s.TimeStamp != nil {
			sigRes.TimestampPresent = true
			sigRes.TimestampValid = (s.TimestampStatus == "valid")
			sigRes.TimestampTime = &s.TimeStamp.Time

			if s.TimestampTrusted {
				sigRes.TimestampTrust = "trusted"
			} else if s.TimestampStatus == "valid" {
				sigRes.TimestampTrust = "untrusted"
			} else {
				sigRes.TimestampTrust = "unknown"
			}
		}

		result.Signatures = append(result.Signatures, sigRes)
	}

	if len(result.Signatures) == 0 && result.Error != "" {
		result.Status = StatusVerificationError
	}

	if len(result.Signatures) == 0 && result.Error == "" {
		result.Status = StatusUnsigned
		result.StatusDetail = "El documento actual no contiene una firma digital verificable."
	}

	return result
}
