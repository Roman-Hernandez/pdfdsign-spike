# Firma y verificación de PDFs

Spike de investigación en Go con `github.com/digitorus/pdfsign v0.9.0` oficial, sin forks. Esta guía permite comprobar el código localmente con recursos propios. No incluye certificados, claves, PDFs, imágenes de firma ni resultados del benchmark; esos archivos permanecen excluidos de Git.

## Requisitos

- Go compatible con la versión declarada en `go.mod`: **1.27.1 o posterior compatible**. Si Go descarga automáticamente el toolchain, necesita acceso a Internet.
- Git para clonar y acceso a los módulos Go para la primera compilación, o una caché previamente preparada.
- Para esta guía, macOS o Linux con shell POSIX y permisos de archivos. Windows requiere adaptar rutas/comandos y revisar el control de permisos de la clave; no se ha comprobado allí.
- Para el benchmark: Bash, `seq`, `xargs` con `-P`, `awk` y `date`.
- Internet para FreeTSA y, si se habilitan, consultas OCSP/CRL. La firma puede ejecutarse sin TSA mediante `-tsa=`; esto no elimina la descarga inicial de módulos.

No se necesitan pdfcpu, Python ni herramientas externas de edición PDF.

## Preparar el proyecto

```bash
git clone https://github.com/Roman-Hernandez/pdfdign-spike.git
cd pdfdign-spike
go version
go mod download
go build ./cmd/...
mkdir -p .local/test-certs testdata output
```

`go build` comprueba compilación, no firma ni genera PDFs. Ejecuta los comandos siguientes desde la raíz del proyecto.

## Preparar los archivos locales

Obtén los certificados y la clave por un canal autorizado y copia tus recursos existentes. El proyecto no los descarga ni genera. No publiques una clave privada ni una imagen personal de firma.

| Ruta utilizada en los ejemplos | Contenido necesario |
|---|---|
| `testdata/prueba-sign-spike.pdf` | PDF de entrada sin firmas para la primera operación; utiliza un documento de prueba sin información personal |
| `.local/test-certs/certificate.pem` | Un certificado X.509 del firmante en PEM |
| `.local/test-certs/private-key.pem` | Clave RSA correspondiente, en PEM PKCS#1 o PKCS#8 sin cifrar; el cargador no admite claves protegidas por contraseña |
| `.local/test-certs/lacuna-ca-test-v7.pem` | Certificado intermedio de laboratorio, para incluir la cadena y ayudar a verificarla |
| `.local/test-certs/lacuna-root-test-v3.pem` | Raíz de laboratorio elegida explícitamente como confiable |
| `testdata/firma.png` | PNG/JPEG opcional para la apariencia; puedes aportar una imagen genérica |

Los nombres Lacuna corresponden al entorno original. Si no dispones de esos recursos, utiliza tus propios certificados y cambia las rutas de los comandos. No cambies únicamente los nombres de archivo para simular una cadena: los certificados deben corresponder realmente entre sí.

```bash
chmod 600 .local/test-certs/private-key.pem
```

El certificado debe estar vigente, permitir `digitalSignature` y corresponder a la clave. La confianza explícita actual se verifica para los usos EmailProtection o ClientAuth: no se acredita compatibilidad con cualquier política de certificado de firma documental. Las fechas y políticas de certificados distintos pueden producir resultados diferentes.

`-chain` incorpora certificados adicionales; no los convierte en confiables. Es opcional y debe omitirse si no hay una cadena adicional. No uses un bundle vacío. `-roots` y `-intermediates` también son opcionales: sin raíces, la confianza configurada queda **NO COMPROBADA**.

## Firmar con imagen y metadatos

El archivo de salida debe ser nuevo; el comando no sobrescribe archivos existentes.

```bash
go run ./cmd/pdfsign-spike \
  -input testdata/prueba-sign-spike.pdf \
  -output output/nueva-firma.pdf \
  -cert .local/test-certs/certificate.pem \
  -key .local/test-certs/private-key.pem \
  -chain .local/test-certs/lacuna-ca-test-v7.pem \
  -image testdata/firma.png \
  -reason 'Firma de prueba' \
  -location 'Laboratorio de pruebas' \
  -contact 'pruebas@example.com'
```

FreeTSA está activada por defecto: un fallo del servicio impide completar la firma. `PDFSIGN_TSA_URL` cambia el servicio y `-tsa URL` tiene prioridad. Para comprobar firma local sin timestamp ni imagen:

```bash
go run ./cmd/pdfsign-spike \
  -input testdata/prueba-sign-spike.pdf \
  -output output/firma-local.pdf \
  -cert .local/test-certs/certificate.pem \
  -key .local/test-certs/private-key.pem \
  -visible=false -tsa=
```

Este segundo ejemplo no incluye cadena adicional ni sello de tiempo. No debe interpretarse como una comprobación de TSA.

La apariencia es nativa de pdfsign. La imagen conserva su proporción dentro del ancho/alto configurado. Sin `-image`, la apariencia muestra el nombre del certificado; `-image-as-watermark` superpone el nombre sobre la imagen. Organización, cargo y layout personalizado no tienen campos visuales públicos. Razón, ubicación y contacto son metadatos, no texto del PNG.

Opciones: `-page 1 -x 50 -y 50 -width 300 -height 70`, en puntos PDF. Sin coordenadas explícitas se coloca en la esquina inferior izquierda de la caja de página, con margen de 50 puntos. No se compensa automáticamente la rotación.

## Verificar

Compila un ejecutable para obtener directamente sus códigos de salida:

```bash
go build -o pdfverify-spike ./cmd/pdfverify-spike
./pdfverify-spike \
  -verbose -measure \
  -roots .local/test-certs/lacuna-root-test-v3.pem \
  -intermediates .local/test-certs/lacuna-ca-test-v7.pem \
  output/nueva-firma.pdf
echo "$?"
```

Para comprobar integridad sin configurar confianza:

```bash
./pdfverify-spike -verbose output/firma-local.pdf
```

| Código del ejecutable | Resultado |
|---|---|
| 0 | Integridad válida; no acredita confianza ni revocación |
| 1 | Error de procesamiento o configuración |
| 2 | Firma ausente |
| 3 | Firma criptográficamente inválida |
| 4 | Bytes posteriores a la última firma |

También puedes usar `go run ./cmd/pdfverify-spike`, pero `go run` no conserva necesariamente como código del proceso el código exacto del programa: utiliza el ejecutable para automatizar comprobaciones.

Revisa separadamente integridad, confianza configurada, vigencia, revocación y TSA. Una raíz Lacuna de laboratorio no acredita confianza pública ni aceptación jurídica. `NOT_CHECKED` no significa certificado no revocado. Las advertencias X.509 se conservan; la confianza TSA es independiente de la del firmante.

Para permitir consultas OCSP/CRL disponibles en la biblioteca, agrega `-external`. Requiere los servicios correspondientes y no garantiza obtener un estado concluyente. CRL permanece UNKNOWN en el adaptador actual cuando no puede autenticar la evidencia expuesta.

## Firmar de nuevo

```bash
go run ./cmd/pdfsign-spike \
  -input output/nueva-firma.pdf \
  -output output/segunda-firma.pdf \
  -cert .local/test-certs/certificate.pem \
  -key .local/test-certs/private-key.pem \
  -chain .local/test-certs/lacuna-ca-test-v7.pem \
  -image testdata/firma.png

./pdfverify-spike -verbose output/segunda-firma.pdf
```

Sin coordenadas explícitas, la segunda firma aparece abajo a la derecha. Para la tercera y posteriores proporciona `-x` y `-y`, o usa `-visible=false`. La biblioteca recibe el PDF original y escribe una revisión incremental; el código comprueba preservación de bytes y verifica las firmas antes de publicar el resultado.

El tipo predeterminado es aprobación. Una cuarta firma de otro firmante requiere otro certificado y su clave correspondiente; cambiar nombre o PNG no cambia la identidad criptográfica. La ubicación visible debe revisarse en un lector PDF para evitar tapar contenido.

## Certificación: limitación de la versión evaluada

`-type certification -permission 1|2|3 -visible=false` permite investigar la salida sobre un PDF sin firmas. **pdfsign v0.9.0 genera la transformación DocMDP, pero omite el enlace Perms/DocMDP en el catálogo:** no se acredita certificación completa aunque la firma verifique criptográficamente. La Spike rechaza conservadoramente firmas posteriores en documentos certificados o con restricciones FieldMDP. No incorpora un parche para simular cumplimiento.

## Medición y benchmark

`-measure` muestra tiempo de pared, asignaciones, heap actual/delta y ciclos GC. No mide RSS ni pico real de memoria. En firma incluye creación de apariencia y controles internos; excluye carga inicial de clave/imagen. El tiempo de TSA puede dominar la operación.

El script `benchmark-firmas.sh` utiliza las rutas fijas de la tabla anterior, salvo la imagen, que no necesita. Compila primero el binario esperado:

```bash
go build -o pdfsign-bench ./cmd/pdfsign-spike
bash benchmark-firmas.sh 10 2
```

Los argumentos son total de operaciones y concurrencia, ambos enteros positivos. El ejemplo realiza diez firmas con dos procesos concurrentes. El script crea PDFs y utiliza FreeTSA por defecto: ejecútalo solo cuando quieras realizar esa comprobación y utilizar el servicio. No es un benchmark exclusivamente criptográfico ni desconectado de la red. Puedes seleccionar un servicio controlado mediante `PDFSIGN_TSA_URL`; el script actual no expone una opción para desactivar TSA.

Los resultados quedan en `output/benchmark/carga-10-2/`: `firma-N.pdf`, `firma-N.log` y `exit-N.txt`. El resumen cuenta éxito por código 0 y existencia de un PDF no vacío. El proceso de firma ejecuta verificaciones internas; esto no demuestra confianza pública, revocación ni conformidad DocMDP. El script no ejecuta una fase independiente de benchmark del verificador ni informa un pico de memoria.

**Antes de repetir los mismos parámetros**, mueve la carpeta de resultados anterior a otra ubicación: los destinos existentes provocan errores de sobrescritura. Conserva los logs de fallos; el código de salida global del script no garantiza que todas las firmas hayan sido satisfactorias.

Para medir una verificación individual:

```bash
./pdfverify-spike -measure -verbose output/segunda-firma.pdf
```

Para comparar resultados registra equipo, sistema operativo, versión Go, tamaño/páginas del PDF, número de firmas, total/concurrencia, TSA usada, errores y varias repeticiones. Los tiempos de otra máquina no son resultados reproducibles exactos ni evidencias de capacidad productiva.

## Pruebas existentes y comprobación de resultados

Los tests de integración están desactivados salvo configuración explícita. Para habilitarlos con recursos existentes:

```bash
PDFSIGN_INTEGRATION=1 \
PDFSIGN_INPUT="$PWD/testdata/prueba-sign-spike.pdf" \
PDFSIGN_CERT="$PWD/.local/test-certs/certificate.pem" \
PDFSIGN_KEY="$PWD/.local/test-certs/private-key.pem" \
go test -v ./tests
```

Esos tests generan PDFs temporales. El escenario TSA se omite sin `PDFSIGN_TSA_URL`; los tests de integración no configuran la apariencia nativa ni prueban confianza pública. Un resultado con tests omitidos no demuestra su funcionamiento. El test de certificación comprueba generación y rechazo conservador de otra firma; no acredita conformidad DocMDP.

Para conservar evidencia local, guarda el PDF de entrada, los firmados, comandos/configuración y salidas de verificación, sin divulgar claves. Comprueba visualmente en un lector independiente la imagen y posición; contrasta las firmas con un validador externo si necesitas interoperabilidad. El éxito en un lector no garantiza aceptación universal. Las salidas y recursos locales quedan ignorados por Git.

Consulta todas las opciones con:

```bash
go run ./cmd/pdfsign-spike -help
go run ./cmd/pdfverify-spike -help
```

## Problemas habituales

| Mensaje / situación | Qué revisar |
|---|---|
| Archivo no encontrado | Los recursos locales no se incluyen al clonar; aporta los archivos o corrige las rutas |
| PEM vacío / inválido | Debe contener certificados reales en formato PEM; omite chain si no es necesario |
| Permisos de clave rechazados | Ejecuta chmod 600 sobre tu clave |
| Certificado fuera de vigencia o clave diferente | Usa certificado vigente y la clave correspondiente; no se relajan esas comprobaciones |
| Salida ya existente | Elige destino nuevo o archiva la ejecución anterior |
| Error TSA | Revisa conectividad/servicio; usa -tsa= únicamente si aceptas comprobar sin timestamp |
| Página/rectángulo inválido | Selecciona página existente y ajusta dimensiones/posición |
| Confianza no comprobada / no confiable | Revisa raíz, intermedias, vigencia y usos; la integridad puede ser válida independientemente |

El repositorio permite repetir el procedimiento con recursos propios. Reproducir los resultados originales de Lacuna requiere esos mismos artefactos y condiciones; no se suministran ni se garantiza que sus certificados o servicios sigan disponibles/vigentes.
