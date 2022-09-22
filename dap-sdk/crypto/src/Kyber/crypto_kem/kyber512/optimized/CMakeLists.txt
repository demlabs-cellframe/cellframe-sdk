cmake_minimum_required(VERSION 3.10)

project (dap_crypto_kyber512 C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

file(GLOB DAP_CRYPTO_KYBER512_SOURCES
    aes256ctr.c
    cbd.c
    fips202_kyber.c
    indcpa.c
    kem.c
    ntt_kyber.c
    poly_kyber.c
    polyvec.c
    reduce_kyber.c
    sha256_kyber.c
    sha512_kyber.c
    symmetric-aes.c
    symmetric-shake.c
    verify.c
)

file(GLOB DAP_CRYPTO_KYBER512_HEADERS
    aes256ctr.h
    cbd.h
    fips202_kyber.h
    indcpa.h
    kem.h
    kyber512.h
    ntt_kyber.h
    params.h
    poly_kyber.h
    polyvec.h
    reduce_kyber.h
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

