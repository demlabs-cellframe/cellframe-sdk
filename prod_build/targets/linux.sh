#!/bin/bash -e

set -e

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  TARGET=$(readlink "$SOURCE")
  if [[ $TARGET == /* ]]; then
    echo "SOURCE '$SOURCE' is an absolute symlink to '$TARGET'"
    SOURCE=$TARGET
  else
    DIR=$( dirname "$SOURCE" )
    echo "SOURCE '$SOURCE' is a relative symlink to '$TARGET' (relative to '$DIR')"
    SOURCE=$DIR/$TARGET # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  fi
done
echo "SOURCE is '$SOURCE'"
RDIR=$( dirname "$SOURCE" )
DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
HERE="$DIR"

if [ "$CROSS_ARCH" = "arm64" ]; then
    echo "Cross-compiling cellframe-sdk for ARM64"
    CMAKE=(cmake-arm64)
    MAKE=(make)
    export OPENSSL_ROOT_DIR="/opt/openssl-arm64"
    export OPENSSL_LIBS="${OPENSSL_ROOT_DIR}/lib/libssl.a ${OPENSSL_ROOT_DIR}/lib/libcrypto.a -ldl"
    export OPENSSL_INCLUDES="${OPENSSL_ROOT_DIR}/include/"
elif [ "$CROSS_ARCH" = "arm32" ]; then
    echo "Cross-compiling cellframe-sdk for ARM32"
    CMAKE=(cmake-arm32)
    MAKE=(make)
    export OPENSSL_ROOT_DIR="/opt/openssl-arm32"
    export OPENSSL_LIBS="${OPENSSL_ROOT_DIR}/lib/libssl.a ${OPENSSL_ROOT_DIR}/lib/libcrypto.a -ldl"
    export OPENSSL_INCLUDES="${OPENSSL_ROOT_DIR}/include/"
else
    CMAKE=(cmake)
    MAKE=(make)
fi

echo "Linux target"
echo "CMAKE=${CMAKE[@]}"
echo "MAKE=${MAKE[@]}"
