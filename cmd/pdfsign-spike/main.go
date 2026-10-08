package main

import (
	"bytes"
	"crypto/x509"
	"flag"
	"fmt"
	"image"
	"math"
	"os"
	"path/filepath"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	"pdfsing_test/internal/certificate"
	"pdfsing_test/internal/measurement"
	"pdfsing_test/internal/signing"
	"pdfsing_test/internal/verification"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	input := flag.String("input", "", "PDF de entrada")
	output := flag.String("output", "", "PDF de salida nuevo")
	certPath := flag.String("cert", "", "Certificado del firmante PEM")
	keyPath := flag.String("key", "", "Llave RSA PEM")
	chainPath := flag.String("chain", "", "Cadena PEM para incorporar a la firma (opcional)")
	rootsPath := flag.String("roots", "", "Raíces confiables para verificar el resultado (opcional)")
	intermediatesPath := flag.String("intermediates", "", "Intermedias para verificar (opcional)")
	imagePath := flag.String("image", "", "PNG/JPEG para apariencia nativa (opcional)")
	visible := flag.Bool("visible", true, "Apariencia nativa; solo approval")
	page := flag.Uint("page", 1, "Página de apariencia, desde 1")
	x := flag.Float64("x", 50, "Coordenada X inferior izquierda, puntos PDF")
	y := flag.Float64("y", 50, "Coordenada Y inferior izquierda, puntos PDF")
	width := flag.Float64("width", 300, "Ancho de apariencia, puntos PDF")
	height := flag.Float64("height", 70, "Alto de apariencia, puntos PDF")
	watermark := flag.Bool("image-as-watermark", false, "Mostrar nombre sobre la imagen")
	location := flag.String("location", "", "Ubicación del firmante")
	reason := flag.String("reason", "", "Razón de firma")
	contact := flag.String("contact", "", "Contacto")
	signatureType := flag.String("type", "approval", "approval o certification")
	permission := flag.Uint("permission", 0, "DocMDP 1/2/3 para certification; 0 usa 1")
	measure := flag.Bool("measure", false, "Medir firma y verificación con runtime.MemStats")
	verbose := flag.Bool("verbose", false, "Mostrar detalles de verificación")
	tsaURL := os.Getenv("PDFSIGN_TSA_URL")
	if tsaURL == "" {
		tsaURL = "https://freetsa.org/tsr"
	}
	tsa := flag.String("tsa", tsaURL, "TSA RFC 3161; -tsa= desactiva timestamp")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *output == "" || *certPath == "" || *keyPath == "" {
		return fmt.Errorf("indique -input, -output, -cert y -key")
	}
	certType := sign.ApprovalSignature
	switch *signatureType {
	case "approval":
	case "certification":
		certType = sign.CertificationSignature
	default:
		return fmt.Errorf("-type debe ser approval o certification")
	}
	if (*signatureType == "approval" && *permission != 0) || *permission > 3 {
		return fmt.Errorf("-permission solo permite 1/2/3 con certification")
	}
	cert, err := certificate.LoadCertificate(*certPath)
	if err != nil {
		return err
	}
	key, err := certificate.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	chain, err := certificate.LoadCertificates(*chainPath)
	if err != nil {
		return err
	}
	roots, err := certificate.LoadPool(*rootsPath)
	if err != nil {
		return err
	}
	intermediates, err := certificate.LoadPool(*intermediatesPath)
	if err != nil {
		return err
	}
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	appearance := sign.Appearance{Visible: *visible, Page: uint32(*page),
		LowerLeftX: *x, LowerLeftY: *y, UpperRightX: *x + *width, UpperRightY: *y + *height,
		ImageAsWatermark: *watermark}
	if *visible {
		if certType != sign.ApprovalSignature {
			return fmt.Errorf("pdfsign v0.9.0 solo admite apariencia visible para approval; use -visible=false")
		}
		if *page == 0 || uint64(*page) > uint64(^uint32(0)) || !(*width >= 1) || !(*height >= 1) {
			return fmt.Errorf("indique página desde 1 y ancho/alto de al menos 1 punto")
		}
		for _, coordinate := range []float64{*x, *y, appearance.UpperRightX, appearance.UpperRightY} {
			if math.IsNaN(coordinate) || math.IsInf(coordinate, 0) {
				return fmt.Errorf("las coordenadas de apariencia deben ser finitas")
			}
		}
		if *imagePath != "" {
			appearance.Image, err = os.ReadFile(*imagePath)
			if err != nil {
				return err
			}
			if len(appearance.Image) == 0 {
				return fmt.Errorf("imagen de apariencia vacía")
			}
			config, _, err := image.DecodeConfig(bytes.NewReader(appearance.Image))
			if err != nil {
				return fmt.Errorf("leer dimensiones de imagen: %w", err)
			}
			scale := math.Min(*width/float64(config.Width), *height/float64(config.Height))
			appearance.UpperRightX = *x + float64(config.Width)*scale
			appearance.UpperRightY = *y + float64(config.Height)*scale
		}
		explicitPosition := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "x" || f.Name == "y" {
				explicitPosition = true
			}
		})
		if !explicitPosition {
			count, _, _, err := verification.SigningPolicy(*input)
			if err != nil {
				return err
			}
			if count > 1 {
				return fmt.Errorf("para la tercera firma o posteriores indique -x y -y para evitar superposición")
			}
			if err := positionAppearance(*input, &appearance, count == 1); err != nil {
				return err
			}
		}
	} else if *imagePath != "" || *watermark {
		return fmt.Errorf("-image e -image-as-watermark requieren -visible=true")
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		return err
	}
	opts := signing.Options{CertType: certType, DocMDPPerm: sign.DocMDPPerm(*permission), Name: name, Location: *location, Reason: *reason, Contact: *contact, TSAURL: *tsa, Appearance: appearance}
	if len(chain) > 0 {
		opts.CertificateChains = [][]*x509.Certificate{append([]*x509.Certificate{cert}, chain...)}
	}
	finish := measurement.Start(*measure, "Firma (incluye controles de preservación)")
	err = signing.Sign(*input, *output, cert, key, opts)
	finish()
	if err != nil {
		return err
	}
	finish = measurement.Start(*measure, "Verificación")
	result, err := verification.VerifyWithOptions(*output, verification.Options{Roots: roots, Intermediates: intermediates})
	finish()
	if err != nil {
		return err
	}
	fmt.Printf("Documento: %s\n\n", *output)
	verification.Print(os.Stdout, result, *verbose)
	if result.Status != verification.StatusValid {
		return fmt.Errorf("verificación criptográfica no satisfactoria")
	}
	return nil
}

// positionAppearance uses the existing reader only; pdfsign writes the appearance.
func positionAppearance(path string, appearance *sign.Appearance, right bool) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("leer página para apariencia: %v", recovered)
		}
	}()
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	reader, err := pdf.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	if int(appearance.Page) > reader.NumPage() {
		return fmt.Errorf("la página solicitada no existe")
	}
	var box pdf.Value
	for _, key := range []string{"CropBox", "MediaBox"} {
		for value := reader.Page(int(appearance.Page)).V; !value.IsNull(); value = value.Key("Parent") {
			if candidate := value.Key(key); !candidate.IsNull() {
				box = candidate
				break
			}
		}
		if !box.IsNull() {
			break
		}
	}
	if box.Len() != 4 {
		return fmt.Errorf("caja de página no disponible; indique -x y -y")
	}
	w := appearance.UpperRightX - appearance.LowerLeftX
	h := appearance.UpperRightY - appearance.LowerLeftY
	left, bottom, rightEdge, top := box.Index(0).Float64(), box.Index(1).Float64(), box.Index(2).Float64(), box.Index(3).Float64()
	if w > rightEdge-left-100 || h > top-bottom-100 {
		return fmt.Errorf("apariencia demasiado grande para la página; reduzca -width o -height")
	}
	appearance.LowerLeftX = left + 50
	if right {
		appearance.LowerLeftX = rightEdge - 50 - w
	}
	appearance.LowerLeftY = bottom + 50
	appearance.UpperRightX = appearance.LowerLeftX + w
	appearance.UpperRightY = appearance.LowerLeftY + h
	return nil
}
