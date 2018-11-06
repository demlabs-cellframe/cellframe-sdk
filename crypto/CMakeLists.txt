cmake_minimum_required(VERSION 3.0)
if(TARGET dap_crypto)
    return() # The project has already been built.
endif()
project (dap_crypto)

include(FindPkgConfig)

file(GLOB CRYPTO_SRCS *.c rand/*.c IAES/*.c sha3/*.c MSRLN/*.c DeFeo_Scheme/*.c)
file(GLOB CRYPTO_HEADERS *.h rand/*.h IAES/*.h sha3/*.h MSRLN/*.h DeFeo_Scheme/*.h)

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS}
    ${LIBOQS_SRCS} ${CRYPTO_HEADERS} ${LIBOQS_HEADERS})

target_include_directories(dap_crypto INTERFACE . rand IAES)
target_link_libraries(dap_crypto dap_core m )
