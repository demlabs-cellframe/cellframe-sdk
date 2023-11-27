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


FILL_VERSION()
{
    source "${HERE}/../version.mk"

    VERSION_UPDATE="s|VERSION_MAJOR|${VERSION_MAJOR}|g"
    BUILD_UPDATE="s|VERSION_MINOR|${VERSION_MINOR}|g"
    MAJOR_UPDATE="s|VERSION_PATCH|${VERSION_PATCH}|g"

    for TEMPLATE in "$@"; do
        sed \
            -e "${VERSION_UPDATE}" \
            -e "${BUILD_UPDATE}" \
            -e "${MAJOR_UPDATE}" \
            -i "${TEMPLATE}"
    done
}

PACK() 
{
    
    DIST_DIR=$1
    BUILD_DIR=$2
    OUT_DIR=$3

    cd $BUILD_DIR
    cpack ./
    cp *.deb ${OUT_DIR}
}
