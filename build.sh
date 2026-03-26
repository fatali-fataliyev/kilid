#!/bin/bash

set -e

APP_NAME="kld"
SRC="."
VERSION=$(cat version.txt)

PLATFORMS=("windows" "linux" "darwin")
ARCHS=("amd64" "arm64")

for GOOS in "${PLATFORMS[@]}"; do
  for GOARCH in "${ARCHS[@]}"; do
    OUTDIR="build/${APP_NAME}_${VERSION}_${GOOS}_${GOARCH}"
    mkdir -p "$OUTDIR"
    if [ "$GOOS" == "windows" ]; then
      OUTFILE="${OUTDIR}/${APP_NAME}.exe"
    else
      OUTFILE="${OUTDIR}/${APP_NAME}"
    fi
    env GOOS=$GOOS GOARCH=$GOARCH go build -o "$OUTFILE" "$SRC"
    (cd build && zip -r "${APP_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip" "${APP_NAME}_${VERSION}_${GOOS}_${GOARCH}")
    rm -rf "$OUTDIR"
    echo "Built build/${APP_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip"
  done
done
