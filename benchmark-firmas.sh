#!/bin/bash

set -u

TOTAL="${1:-100}"
CONCURRENCIA="${2:-10}"
: "${PDFSIGN_INPUT:?Defina PDFSIGN_INPUT con la ruta del PDF de entrada}"
: "${PDFSIGN_CERT:?Defina PDFSIGN_CERT con la ruta del certificado PEM}"
: "${PDFSIGN_KEY:?Defina PDFSIGN_KEY con la ruta de la clave privada PEM}"
PDFSIGN_CHAIN="${PDFSIGN_CHAIN:-}"
PDFSIGN_BENCH_BIN="${PDFSIGN_BENCH_BIN:-./pdfsign-bench}"
PDFSIGN_OUTPUT_DIR="${PDFSIGN_OUTPUT_DIR:-output/benchmark}"
DIR="${PDFSIGN_OUTPUT_DIR}/carga-${TOTAL}-${CONCURRENCIA}"

if ! [[ "$TOTAL" =~ ^[1-9][0-9]*$ && "$CONCURRENCIA" =~ ^[1-9][0-9]*$ ]]; then
  echo "Total y concurrencia deben ser enteros positivos" >&2
  exit 1
fi
for file in "$PDFSIGN_INPUT" "$PDFSIGN_CERT" "$PDFSIGN_KEY"; do
  if [ ! -f "$file" ]; then
    echo "No existe el archivo: $file" >&2
    exit 1
  fi
done
if [ -n "$PDFSIGN_CHAIN" ] && [ ! -f "$PDFSIGN_CHAIN" ]; then
  echo "No existe la cadena PEM: $PDFSIGN_CHAIN" >&2
  exit 1
fi
if [ ! -f "$PDFSIGN_BENCH_BIN" ]; then
  echo "No existe el ejecutable: $PDFSIGN_BENCH_BIN" >&2
  exit 1
fi

export PDFSIGN_INPUT PDFSIGN_CERT PDFSIGN_KEY PDFSIGN_CHAIN PDFSIGN_BENCH_BIN

mkdir -p "$DIR"

echo "Operaciones: $TOTAL"
echo "Concurrencia: $CONCURRENCIA"

inicio=$(date +%s)

seq 1 "$TOTAL" | xargs -P "$CONCURRENCIA" -I '{}' \
  sh -c '
    i="$1"
    dir="$2"
    set -- -input "$PDFSIGN_INPUT" \
      -output "$dir/firma-$i.pdf" \
      -cert "$PDFSIGN_CERT" \
      -key "$PDFSIGN_KEY"
    if [ -n "$PDFSIGN_CHAIN" ]; then
      set -- "$@" -chain "$PDFSIGN_CHAIN"
    fi

    "$PDFSIGN_BENCH_BIN" "$@" -visible=false \
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
