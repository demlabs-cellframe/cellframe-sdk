#!/bin/bash -e
#IOS BUILD

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

UNAME_OUT="$(uname -s)"
case "${UNAME_OUT}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=ios;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    MSYS_NT*)   MACHINE=Git;;
    *)          MACHINE="UNKNOWN:${UNAME_OUT}"
esac

if [ "$MACHINE" != "ios" ]
then
  echo "Host is $MACHINE, use osx-cross build target"
  if [ -z "$OSXCROSS_QT_ROOT" ]
  then
        echo "Please, export OSXCROSS_QT_ROOT variable, pointing to Qt-builds locations for osxcross environment"
        exit 255
  fi


  if [ -z "$OSXCROSS_QT_VERSION" ]
  then
        echo "Please, export OSXCROSS_QT_VERSION variable, scpecifying Qt-version in OSXCROSS_QT_ROOT directory."
        exit 255
  fi

  echo "Using QT ${OSXCROSS_QT_VERSION} from ${OSXCROSS_QT_ROOT}/${OSXCROSS_QT_VERSION}"

  [ ! -d ${OSXCROSS_QT_ROOT}/${OSXCROSS_QT_VERSION} ] && { echo "No QT ${OSXCROSS_QT_VERSION} found in ${OSXCROSS_QT_ROOT}" && exit 255; }

  $(${OSXCROSS_ROOT}/bin/osxcross-conf)


  export OSXCROSS_HOST=x86_64-apple-darwin20.4
  CMAKE=(cmake -DCMAKE_TOOLCHAIN_FILE=${OSXCROSS_ROOT}/toolchain.cmake)
  echo "${}"

  ##everything else can be done by default make
  MAKE=(make)


else
    echo "Host is $MACHINE, use iOS build target"

    if [ -z "$IOS_TOOLCHAIN_PATH" ]; then
        IOS_TOOLCHAIN_PATH=(${HERE}/../../dap-sdk/cmake/ios.toolchain.cmake)
    fi

    if [ -f "/Users/$USER/Qt/Tools/CMake/CMake.app/Contents/bin/cmake" ]
    then
      CMAKE_PATH=(/Users/$USER/Qt/Tools/CMake/CMake.app/Contents/bin/cmake )
      echo "Found QT cmake at $CMAKE, using it preferable"
    else
      if [ -f "/opt/homebrew/bin/cmake" ]
      then
        CMAKE_PATH=(/opt/homebrew/bin/cmake)
        echo "Found homebrew cmake at $CMAKE, using it"
      else
        echo "Not found cmake at default qt location, asuming it is in PATH"
        CMAKE_PATH=(cmake)
      fi
    fi

    export IOS_TOOLCHAIN_HOST="x86_64-apple-darwin-macho"
    CMAKE=(${CMAKE_PATH} -DCMAKE_TOOLCHAIN_FILE="${IOS_TOOLCHAIN_PATH}")

    MAKE=(make)
fi
