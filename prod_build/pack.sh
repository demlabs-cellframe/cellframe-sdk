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


export SOURCES=${HERE}/../

containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

echo "Pack for cellframe-sdk not implemented yet" && exit 127

Help()
{
   echo "cellframe-sdk pack"
   echo "Usage: pack.sh [--target linux | windows | android] [release | debug]"
}

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      Help
      shift # past argument
      shift # past value
      ;;
    -t|--target)
      TARGET="$2"
      shift # past argument
      shift # past value
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

#all base logic from here


BUILD_TYPE="${1:-release}"
BUILD_OPTIONS="${@:2}"

BUILD_TARGET="${TARGET:-linux}"


#validate input params
. ${HERE}/validate.sh
VALIDATE_TARGET $TARGET
VALIDATE_BUILD_TYPE $BUILD_TYPE

DIST_DIR=${PWD}/build_${BUILD_TARGET}_${BUILD_TYPE}/dist
BUILD_DIR=${PWD}/build_${BUILD_TARGET}_${BUILD_TYPE}/build
OUT_DIR=${PWD}/build_${BUILD_TARGET}_${BUILD_TYPE}/

#we care only about dist dir, i think
[ ! -d ${DIST_DIR} ] && { echo "No build found: $BRAND $BUILD_TARGET" && exit 255; }



echo "Pack [${BUILD_TYPE}] binaries for [$BUILD_TARGET] from [${DIST_DIR}] to [${OUT_DIR}]"

. ${HERE}/packaging/${BUILD_TARGET}.sh

PACK ${DIST_DIR} ${BUILD_DIR} ${OUT_DIR}



