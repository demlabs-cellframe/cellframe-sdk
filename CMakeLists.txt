project(dap C)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(client)
add_subdirectory(http)

include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${dap_crypto_INCLUDE_DIRS}")
include_directories("${dap_http_INCLUDE_DIRS}")
include_directories("${dap_client_INCLUDE_DIRS}")

add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${dap_http_DEFINITIONS}")
add_definitions ("${dap_client_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC IMPORTED libdap.c )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
