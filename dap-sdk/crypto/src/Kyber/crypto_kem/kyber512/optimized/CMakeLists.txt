cmake_minimum_required(VERSION 3.10)

project (dap_crypto_kyber512 C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

file(GLOB DAP_CRYPTO_KYBER512_SOURCES
    aes256ctr.c
    cbd.c
    fips202.c
    indcpa.c
    kem.c
    ntt.c
    poly.c
    polyvec.c
    reduce.c
    sha256.c
    sha512.c
    symmetric-aes.c
    symmetric-shake.c
    verify.c
)

file(GLOB DAP_CRYPTO_KYBER512_HEADERS
    aes256ctr.h
    cbd.h
    fips202.h
    indcpa.h
    kem.h
    kyber512.h
    ntt.h
    params.h
    poly.h
    polyvec.h
    reduce.h
    sha2.h
    speed_print.h
    symmetric.h
    verify.h
)


add_library(${PROJECT_NAME} STATIC ${DAP_CRYPTO_KYBER512_HEADERS} ${DAP_CRYPTO_KYBER512_SOURCES})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto pthread)

target_include_directories(${PROJECT_NAME} PUBLIC .)

if (${BUILD_DAP_CRYPTO_KYBER512_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

