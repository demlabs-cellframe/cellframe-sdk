cmake_minimum_required(VERSION 3.0)
if(TARGET dap_crypto)
    return() # The project has already been built.
endif()
project (dap_crypto)

file(GLOB CRYPTO_SRCS *.c)
file(GLOB CRYPTO_HEADERS *.h)

set(LIBOQS_SRCS
    liboqs/kex_sidh_cln16/kex_sidh_cln16.c
    liboqs/kex_sidh_cln16/SIDH.c
    liboqs/kex_sidh_cln16/SIDH_setup.c
    liboqs/kex_sidh_cln16/sidh_kex.c
    liboqs/kex_sidh_cln16/ec_isogeny.c
    liboqs/kex_sidh_cln16/fpx.c
    liboqs/kex_sidh_cln16/generic/fp_generic.c
    liboqs/kex_rlwe_msrln16/generic/ntt.c
    liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.c
    liboqs/kex_rlwe_msrln16/LatticeCrypto_kex.c
    liboqs/kex_rlwe_msrln16/ntt_constants.c
    liboqs/crypto/sha3/sha3.c
    liboqs/crypto/rand/rand.c
    liboqs/crypto/rand_urandom_aesctr/rand_urandom_aesctr.c
    liboqs/crypto/rand_urandom_chacha20/rand_urandom_chacha20.c
    liboqs/crypto/aes/aes_c.c
    liboqs/crypto/aes/aes_ni.c
    liboqs/crypto/aes/aes.c
    )

set(RND_SRCS
    liboqs/crypto/rand/rand.c
    )

set(LIBOQS_HEADERS
    liboqs/kex_sidh_cln16/kex_sidh_cln16.h
    liboqs/kex_sidh_cln16/SIDH.h
    liboqs/kex_sidh_cln16/SIDH_internal.h
    liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h
    liboqs/kex_rlwe_msrln16/LatticeCrypto_priv.h
    liboqs/kex_rlwe_msrln16/LatticeCrypto.h
    liboqs/crypto/sha3/sha3.h
    liboqs/crypto/rand/rand.h
    liboqs/crypto/rand_urandom_aesctr/rand_urandom_aesctr.h
    liboqs/crypto/rand_urandom_chacha20/rand_urandom_chacha20.h
    liboqs/crypto/aes/aes_local.h
    liboqs/crypto/aes/aes.h
    )

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS}
    ${LIBOQS_SRCS} ${CRYPTO_HEADERS} ${LIBOQS_HEADERS})

target_include_directories(dap_crypto INTERFACE .)

target_link_libraries(dap_crypto dap_core m)
