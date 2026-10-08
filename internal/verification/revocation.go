package verification

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pdfsign/verify"
	"golang.org/x/crypto/ocsp"
)

// applyOCSP validates only an existing response; it creates no revocation service.
// CRL bytes/signature provenance are not exposed by pdfsign v0.9.0, so remain UNKNOWN.
func applyOCSP(result *SignatureResult, leaf, issuer *x509.Certificate, certificate verify.Certificate) {
	response := certificate.OCSPResponse
	if response == nil {
		return
	}
	reject := func(reason string) { result.Revocation = RevocationUnknown; result.RevocationReason = reason }
	if response.SerialNumber == nil || response.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		reject("OCSP no corresponde al certificado del firmante.")
		return
	}
	now := time.Now()
	if response.ThisUpdate.IsZero() || response.ThisUpdate.After(now) || response.NextUpdate.IsZero() || now.After(response.NextUpdate) {
		reject("Vigencia OCSP insuficiente o respuesta caducada.")
		return
	}
	responder := issuer
	if response.Certificate != nil {
		responder = response.Certificate
		if err := responder.CheckSignatureFrom(issuer); err != nil {
			reject("Emisor del respondedor OCSP no verificado: " + err.Error())
			return
		}
		allowed := false
		for _, usage := range responder.ExtKeyUsage {
			if usage == x509.ExtKeyUsageOCSPSigning {
				allowed = true
			}
		}
		if !allowed || now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
			reject("Respondedor OCSP sin autorización o fuera de vigencia.")
			return
		}
	}
	if err := response.CheckSignatureFrom(responder); err != nil {
		reject("Firma OCSP inválida: " + err.Error())
		return
	}
	switch response.Status {
	case ocsp.Good:
		result.Revocation = RevocationGood
		result.RevocationReason = "OCSP autenticado y vigente: GOOD."
	case ocsp.Revoked:
		result.Revocation = RevocationRevoked
		result.RevocationReason = fmt.Sprintf("OCSP autenticado: revocado el %s; estado actual, no conclusión histórica de firma.", response.RevokedAt.Format(time.RFC3339))
	default:
		reject("OCSP autenticado informa UNKNOWN; no equivale a revocado ni GOOD.")
	}
}
