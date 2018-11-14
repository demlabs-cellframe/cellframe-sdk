cmake_minimum_required(VERSION 3.0)
if(TARGET dap_crypto)
    return() # The project has already been built.
endif()
project (dap_crypto)

include(FindPkgConfig)

file(GLOB CRYPTO_SRCS *.c rand/*.c iaes/*.c sha3/*.c msrln/*.c defeo_scheme/*.c)
file(GLOB CRYPTO_HEADERS *.h rand/*.h iaes/*.h sha3/*.h msrln/*.h defeo_scheme/*.h)

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS}
    ${LIBOQS_SRCS} ${CRYPTO_HEADERS} ${LIBOQS_HEADERS})

target_include_directories(dap_crypto INTERFACE . rand IAES)
target_link_libraries(dap_crypto dap_core m )
