package main

import (
	"flag"
	"fmt"
	"os"

	"pdfsing_test/internal/certificate"
	"pdfsing_test/internal/measurement"
	"pdfsing_test/internal/verification"
)

func main() {
	external := flag.Bool("external", false, "Permitir consultas OCSP/CRL")
	measure := flag.Bool("measure", false, "Medir tiempo y memoria de verificación")
	verbose := flag.Bool("verbose", false, "Mostrar detalles técnicos")
	rootsPath := flag.String("roots", "", "Raíces confiables PEM; vacío deja confianza sin comprobar")
	intermediatesPath := flag.String("intermediates", "", "Intermedias PEM")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Uso: pdfverify-spike [opciones] documento.pdf")
		os.Exit(1)
	}
	roots, err := certificate.LoadPool(*rootsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	intermediates, err := certificate.LoadPool(*intermediatesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	finish := measurement.Start(*measure, "Verificación")
	result, err := verification.VerifyWithOptions(flag.Arg(0), verification.Options{External: *external, Roots: roots, Intermediates: intermediates})
	finish()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Documento: %s\n\n", flag.Arg(0))
	verification.Print(os.Stdout, result, *verbose)
	switch result.Status {
	case verification.StatusVerificationError:
		os.Exit(1)
	case verification.StatusUnsigned:
		os.Exit(2)
	case verification.StatusInvalidSignature:
		os.Exit(3)
	case verification.StatusModified:
		os.Exit(4)
	}
}
