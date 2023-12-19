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

if [ -z "$ANDROID_CMAKE_TOOLCHAIN" ]
then
      if [ -z "$ANDROID_NDK_ROOT"]
      then
        echo "Nor ANDROID_CMAKE_TOOLCHAIN nor ANDROID_NDK_ROOT defined!"
            exit 1
      fi
      ANDROID_CMAKE_TOOLCHAIN=${ANDROID_NDK_ROOT}/build/cmake/android.toolchain.cmake
      echo "ANDROID_CMAKE_TOOLCHAIN not defined, but ANDROID_NDK_ROOT is."
      echo "Use ANDROID_CMAKE_TOOLCHAIN as $ANDROID_CMAKE_TOOLCHAIN"
fi

CMAKE=(cmake -DCMAKE_TOOLCHAIN_FILE=${ANDROID_CMAKE_TOOLCHAIN})
MAKE=(make)

echo "Android target"
echo "CMAKE=${CMAKE[@]}"
echo "MAKE=${MAKE[@]}"
