#!/bin/bash

# Define target architectures
ARCHS=("arm64" "x86_64")

# Define target platforms
PLATFORMS=("iphoneos" "iphonesimulator")

# Create a build directory
mkdir -p build/ios

# Generate the configure script
./autogen.sh

for PLATFORM in "${PLATFORMS[@]}"; do
    for ARCH in "${ARCHS[@]}"; do
        echo "🚀 Building libsecp256k1 for architecture: $ARCH on $PLATFORM"

        # Get the correct SDK path
        IOS_SDK=$(xcrun --sdk $PLATFORM --show-sdk-path)

        # Set up cross-compilation flags
        if [ "$PLATFORM" == "iphoneos" ] && [ "$ARCH" == "arm64" ]; then
            HOST="aarch64-apple-darwin"
            TRIPLE="arm64-apple-ios12.0"

        elif [ "$PLATFORM" == "iphonesimulator" ] && [ "$ARCH" == "x86_64" ]; then
            HOST="x86_64-apple-darwin"
            TRIPLE="x86_64-apple-ios12.0"

        elif [ "$PLATFORM" == "iphonesimulator" ] && [ "$ARCH" == "arm64" ]; then
            HOST="aarch64-apple-darwin"
            TRIPLE="arm64-apple-ios12.0-simulator"

        else
            echo "⚠️ Skipping unsupported combination: $ARCH-$PLATFORM"
            continue
        fi

        # Run configure script with iOS flags
        ./configure \
            --host=$HOST \
            --disable-tests \
            --enable-module-recovery \
            --disable-shared \
            --enable-static \
            CC="$(xcrun --find clang) -target $TRIPLE" \
            CFLAGS="-arch $ARCH -isysroot $IOS_SDK -mios-version-min=12.0"

        # Build the library
        make clean && make -j$(sysctl -n hw.ncpu)

        # Save the output
        mv .libs/libsecp256k1.a build/ios/libsecp256k1_${ARCH}_${PLATFORM}.a
    done
done

# Merge architectures into a universal static library using lipo
# build/ios/libsecp256k1_arm64_iphoneos.a \
lipo -create \
    build/ios/libsecp256k1_x86_64_iphonesimulator.a \
    build/ios/libsecp256k1_arm64_iphonesimulator.a \
    -output build/ios/libsecp256k1.a

echo "✅ Finished building universal libsecp256k1.a"
