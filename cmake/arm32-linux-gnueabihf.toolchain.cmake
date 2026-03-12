set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
set(CMAKE_ASM_COMPILER arm-linux-gnueabihf-gcc)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

find_program(QEMU_ARM_STATIC qemu-arm-static qemu-arm HINTS /usr/bin /usr/local/bin)
if(QEMU_ARM_STATIC)
    set(CMAKE_CROSSCOMPILING_EMULATOR "${QEMU_ARM_STATIC};-L;/usr/arm-linux-gnueabihf"
        CACHE STRING "ARM32 QEMU emulator with sysroot" FORCE)
endif()
