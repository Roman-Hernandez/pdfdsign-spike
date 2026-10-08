package verification

import (
	"fmt"
	"io"
)

// Print is shared by both commands; it never changes verification policy.
func Print(w io.Writer, result *Result, verbose bool) {
	fmt.Fprintf(w, "Estado general: %s\nFirmas encontradas: %d\n", result.Status, len(result.Signatures))
	if result.Status == StatusUnsigned || result.Status == StatusVerificationError {
		fmt.Fprintln(w, result.StatusDetail)
		return
	}
	if result.Status == StatusModified {
		fmt.Fprintln(w, result.StatusDetail)
	}
	if verbose && result.Error != "" {
		fmt.Fprintf(w, "Diagnóstico pdfsign: %s\n", result.Error)
	}
	for i, s := range result.Signatures {
		fmt.Fprintf(w, "\nFirma #%d\n----------------------------------------\n", i+1)
		fmt.Fprintf(w, "Integridad criptográfica de la revisión: %s\n", integrity(s.Valid))
		if s.LaterRevision {
			fmt.Fprintln(w, "Hay bytes/revisiones posteriores a esta firma; no equivalen por sí solos a una firma inválida.")
		}
		for _, warning := range s.Warnings {
			fmt.Fprintf(w, "Advertencia: %s\n", warning)
		}
		fmt.Fprintf(w, "Firmante:\n  Nombre: %s\n  Razón: %s\n  Contacto: %s\n  Ubicación: %s\n", s.SignerName, s.Reason, s.Contact, s.Location)
		trust := "NO COMPROBADA"
		if s.TrustScope == "CONFIGURED_ROOTS" {
			trust = "NO CONFIABLE"
		}
		if s.TrustedIssuer {
			trust = "CONFIABLE EN RAÍCES CONFIGURADAS"
		}
		validity := map[string]string{"VALID_NOW": "VIGENTE", "EXPIRED": "VENCIDO", "NOT_YET_VALID": "AÚN NO VIGENTE"}[s.CertificateValidity]
		if validity == "" {
			validity = "NO COMPROBADA"
		}
		revocation := map[RevocationStatus]string{RevocationGood: "NO REVOCADO (GOOD)", RevocationRevoked: "REVOCADO", RevocationUnknown: "DESCONOCIDA", RevocationNotChecked: "NO COMPROBADA"}[s.Revocation]
		fmt.Fprintf(w, "\nCertificado:\n  Confianza configurada: %s\n  Vigencia actual: %s\n  Revocación del firmante: %s\n", trust, validity, revocation)
		if !s.TrustedIssuer && s.IssuerError != "" {
			fmt.Fprintf(w, "  Motivo: %s\n", s.IssuerError)
		}
		fmt.Fprintln(w, "\nTimestamp:")
		if !s.TimestampPresent {
			fmt.Fprintln(w, "  Presente: NO")
		} else {
			tsaTrust := map[string]string{"trusted": "CONFIABLE", "untrusted": "NO CONFIABLE"}[s.TimestampTrust]
			if tsaTrust == "" {
				tsaTrust = "DESCONOCIDA"
			}
			fmt.Fprintf(w, "  Presente: SÍ\n  Integridad: %s\n  Confianza TSA: %s\n", integrity(s.TimestampValid), tsaTrust)
			if s.TimestampTime != nil {
				fmt.Fprintf(w, "  Fecha: %s\n", s.TimestampTime.Format("2006-01-02 15:04:05 MST"))
			}
		}
		if !verbose {
			continue
		}
		fmt.Fprintf(w, "\nDetalles técnicos:\n  Alcance: %s\n  Confianza reportada por pdfsign: %v\n  Fuente temporal: %s\n  Revocación: %s\n", s.TrustScope, s.PubliclyTrustedIssuer, s.TimeSource, s.RevocationReason)
		for _, warning := range s.TimeWarnings {
			fmt.Fprintf(w, "  Advertencia temporal: %s\n", warning)
		}
		for j, cert := range s.Certificates {
			fmt.Fprintf(w, "  Certificado [%d]:\n    Subject: %s\n    Issuer: %s\n    Serial: %s\n    NotBefore: %s\n    NotAfter: %s\n", j+1, cert.Subject, cert.Issuer, cert.Serial, cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))
			if cert.VerifyErr != "" {
				fmt.Fprintf(w, "    Diagnóstico pdfsign: %s\n", cert.VerifyErr)
			}
		}
	}
}

func integrity(valid bool) string {
	if valid {
		return "VÁLIDA"
	}
	return "INVÁLIDA"
}
