#!/bin/bash

set -u

TOTAL="${1:-100}"
CONCURRENCIA="${2:-10}"
DIR="output/benchmark/carga-${TOTAL}-${CONCURRENCIA}"

mkdir -p "$DIR"

echo "Operaciones: $TOTAL"
echo "Concurrencia: $CONCURRENCIA"

inicio=$(date +%s)

seq 1 "$TOTAL" | xargs -P "$CONCURRENCIA" -I '{}' \
  sh -c '
    i="$1"
    dir="$2"

    ./pdfsign-bench \
      -input testdata/prueba-sign-spike.pdf \
      -output "$dir/firma-$i.pdf" \
      -cert .local/test-certs/certificate.pem \
      -key .local/test-certs/private-key.pem \
      -chain .local/test-certs/lacuna-ca-test-v7.pem \
      -visible=false \
      > "$dir/firma-$i.log" 2>&1

    echo "$?" > "$dir/exit-$i.txt"
  ' _ '{}' "$DIR"

fin=$(date +%s)

exitos=0
errores=0

for i in $(seq 1 "$TOTAL"); do
  if [ -f "$DIR/exit-$i.txt" ] &&
     [ "$(cat "$DIR/exit-$i.txt")" = "0" ] &&
     [ -s "$DIR/firma-$i.pdf" ]; then
    exitos=$((exitos + 1))
  else
    errores=$((errores + 1))
  fi
done

duracion=$((fin - inicio))

echo
echo "===== RESULTADOS ====="
echo "Total: $TOTAL"
echo "Exitosas: $exitos"
echo "Fallidas: $errores"
echo "Duración: ${duracion}s"

if [ "$duracion" -gt 0 ]; then
  awk -v ok="$exitos" -v t="$duracion" \
    'BEGIN { printf "Rendimiento: %.2f firmas/s\n", ok/t }'
fi

echo "Resultados: $DIR"
