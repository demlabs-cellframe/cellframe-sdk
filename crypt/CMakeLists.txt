cmake_minimum_required(VERSION 2.8)
project (dapcrypt)
  
set(CRYPT_SRCS enc.c  enc_fnam2.c enc_key.c  )
 
include_directories("${dapcore_INCLUDE_DIRS}")
add_definitions ("${dapcore_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${CRYPT_SRCS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
