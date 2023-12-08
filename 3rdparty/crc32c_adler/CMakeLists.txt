#
#  DESCRIPTION: A miminal cmake script to be used to produce CRC32 Addler static library
#
#  AUTHOR: Ruslan R. Laishev
#
#  CREATION DATE: 14-NOV-2022
#
#  MODIFICATION HISTORY:
#
cmake_minimum_required(VERSION 3.10)
project(crc32c_adler)

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall" )
set( SRCS crc32c_adler.c  crc32c_adler.h)
add_library(crc32c_adler  STATIC ${SRCS})

target_link_libraries(crc32c_adler)

if(NOT ANDROID)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} pthread)
endif()
