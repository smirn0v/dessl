#!/usr/bin/env bash
clang -I`pwd`/build -L`pwd`/build -o build/dessl main.c -framework CoreFoundation -framework Security -ldessl
