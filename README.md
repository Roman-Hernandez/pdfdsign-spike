# Firma y verificación de PDFs

Spike en Go para evaluar `github.com/digitorus/pdfsign v0.9.0`, con certificados Lacuna de laboratorio.

## Firmar

```bash
go run ./cmd/pdfsign-spike \
  -input testdata/prueba-sign-spike.pdf \
  -output output/nueva-firma.pdf \
  -cert .local/test-certs/certificate.pem \
  -key .local/test-certs/private-key.pem \
  -chain .local/test-certs/lacuna-ca-test-v7.pem \
  -image testdata/firma.png \
  -reason 'Firma de prueba'
```

El archivo de salida debe ser nuevo. La clave debe tener permisos `0600`. La imagen conserva su proporción dentro del ancho y alto indicados.

Opciones de apariencia: `-page 1 -x 50 -y 50 -width 300 -height 70`. Usa `-image-as-watermark` para superponer el nombre o `-visible=false` para firmar sin apariencia. TSA está activada por defecto; `-tsa=` la desactiva.

## Verificar

```bash
go run ./cmd/pdfverify-spike \
  -verbose \
  -roots .local/test-certs/lacuna-root-test-v3.pem \
  -intermediates .local/test-certs/lacuna-ca-test-v7.pem \
  output/nueva-firma.pdf
```

La confianza en estas raíces es de laboratorio. Una firma íntegra no acredita confianza pública ni revocación comprobada.

## Firmar de nuevo

```bash
go run ./cmd/pdfsign-spike \
  -input output/nueva-firma.pdf \
  -output output/segunda-firma.pdf \
  -cert .local/test-certs/certificate.pem \
  -key .local/test-certs/private-key.pem \
  -chain .local/test-certs/lacuna-ca-test-v7.pem \
  -image testdata/firma.png
```

Sin coordenadas explícitas, la primera firma aparece abajo a la izquierda y la segunda abajo a la derecha, con margen de 50 puntos respecto a la caja de página. Para la tercera o posteriores indica `-x` y `-y`. El tipo predeterminado sigue siendo aprobación.

Agrega `-measure` a cualquiera de los comandos para mostrar tiempo y memoria. Consulta todas las opciones con `go run ./cmd/pdfsign-spike -help` o `go run ./cmd/pdfverify-spike -help`.
