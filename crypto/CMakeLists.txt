cmake_minimum_required(VERSION 3.0)
if(TARGET dap_crypto)
    return() # The project has already been built.
endif()
project (dap_crypto)

file(GLOB CRYPTO_SRCS *.c rand/*.c iaes/*.c sha3/*.c msrln/*.c defeo_scheme/*.c sig_bliss/*.c)
file(GLOB CRYPTO_HEADERS *.h rand/*.h iaes/*.h sha3/*.h msrln/*.h defeo_scheme/*.h sig_bliss/*.h)

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS}
    ${LIBOQS_SRCS} ${CRYPTO_HEADERS} ${LIBOQS_HEADERS})

target_include_directories(dap_crypto PRIVATE rand iaes sha3 msrln defeo_scheme sig_bliss)
target_include_directories(dap_crypto INTERFACE . sha3)

target_link_libraries(dap_crypto dap_core m)
