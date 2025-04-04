#!/usr/bin/env bash

set -e

export ARCH=arm64
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
export CGO_ENABLED=1
export CGO_CFLAGS="-isysroot $SDKROOT -arch $ARCH"
export CGO_LDFLAGS="-isysroot $SDKROOT -arch $ARCH"
export GOOS=darwin
export GOARCH="$ARCH"

go build -ldflags=-w -trimpath -v -o "build/libdessl.a" -buildmode c-archive
clang -I`pwd`/build -L`pwd`/build -o build/dessl ./c_example/main.c -framework CoreFoundation -framework Security -ldessl
