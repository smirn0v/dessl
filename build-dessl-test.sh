#!/usr/bin/env bash
clang -I`pwd`/build -L`pwd`/build -o build/dessl ./c_example/main.c -framework CoreFoundation -framework Security -ldessl
