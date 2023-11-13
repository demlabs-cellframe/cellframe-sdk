#!/bin/bash
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



containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}


TARGETS=(linux windows android osx)
BUILD_TYPES=(release debug rwd)

VALIDATE_TARGET()
{
    containsElement "$BUILD_TARGET" "${TARGETS[@]}"  || {
        echo "Such target not implemented [$BUILD_TARGET]"
        echo "Available targets are [${TARGETS[@]}]"
        exit 255
    }
}

VALIDATE_BUILD_TYPE()
{
    containsElement "$BUILD_TYPE" "${BUILD_TYPES[@]}"  || {
        echo "Unknown build typed [$BUILD_TYPE]"
        echo "Available types are [${BUILD_TYPES[@]}]"
        exit 255
    }
}

