#!/usr/bin/env bash

set -e

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "ERROR: ANDROID_NDK_HOME environment variable is not set"
    echo "Please set it first:"
    echo "export ANDROID_NDK_HOME=</path/to/your/ndk>"
    echo "i.e export ANDROID_NDK_HOME=/Users/USERNAME/Library/Android/sdk/ndk/29.0.13113456"
    exit 1
fi

if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "ERROR: NDK directory does not exist: $ANDROID_NDK_HOME"
    exit 1
fi

export API_LEVEL=21

# Define ABIs and their corresponding Go architectures and compilers
ABIS=(
    "armeabi-v7a arm $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi$API_LEVEL-clang"
    "arm64-v8a arm64 $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android$API_LEVEL-clang"
    "x86 386 $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android$API_LEVEL-clang"
    "x86_64 amd64 $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android$API_LEVEL-clang"
)

# export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64
# export CC=$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang
# export CXX=$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang++
export CGO_ENABLED=1
export GOOS=android
# export CGO_CFLAGS="-I$ANDROID_NDK_HOME/sysroot/usr/include -target aarch64-none-linux-android$API_LEVEL"
# export CGO_LDFLAGS="-target aarch64-none-linux-android$API_LEVEL"

# Loop through each ABI and build
for abi in "${ABIS[@]}"; do
    read -r abi_name goarch cc <<< "$abi"
    echo "Building for $abi_name..."

    export GOARCH=$goarch
    export CC=$cc
    export CXX="$CC++"

    # Build the shared library
    # go build -buildmode=c-shared -o "build/libdessl_$abi_name.so" main.go

    go build -buildmode=c-shared -ldflags="-w -s" -v -o "build/$abi_name/libdessl.so"

    echo "Done building for $abi_name."
done

# Сборка
# go build -ldflags="-w -s" -v -o "build/libdessl.a"