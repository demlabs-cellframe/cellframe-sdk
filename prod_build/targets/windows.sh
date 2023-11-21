
#!/bin/bash -e
#WINDWOS BUILD IS SUPPORTED BY MXE
#HAVE TO PROVIDE MXE ROOT DIRECTORY
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


if [ -z "$MSYSTEM_PREFIX" ] 
then
      echo "Not MSYS2 env, try MXE"
      if [ -z "$MXE_ROOT" ]
      then
            echo "Please, export MXE_ROOT variable, pointing to MXE environment root (we will use qt, make shure it was built)"
            echo "To build mxe, go to https://github.com/mxe/mxe, clone it, and do \"make qt5\" within it. Install dependencies if it says so." 
            exit 255
      else
            #cmake command
            #mxe install prefix if configured by mxe, need to change it
            CMAKE=(${MXE_ROOT}/usr/bin/x86_64-w64-mingw32.static-cmake ) 
            export PATH=${MXE_ROOT}/usr/bin:$PATH
            #everything else can be done by default make
            MAKE=(make)

            echo "Windows target"
            echo "CMAKE=${CMAKE[@]}"
            echo "MAKE=${MAKE[@]}"
      fi
else
      #cmake command
      #mxe install prefix if configured by mxe, need to change it
      CMAKE=(cmake -G "MSYS Makefiles") 
      MAKE=(make)

      echo "Windows target"
      echo "CMAKE=${CMAKE[@]}"
      echo "MAKE=${MAKE[@]}"
fi

