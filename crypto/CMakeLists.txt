cmake_minimum_required(VERSION 2.8)
project (dap_crypto)

 
set(CRYPTO_SRCS
        dap_enc.c
        dap_enc_base64.c
        dap_enc_aes.c
        dap_enc_newhope.c
        dap_enc_msrln16.c
        dap_enc_key.c
        dap_enc_sidh16.c
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
     libdap/crypto/liboqs/crypto/rand/rand.c
    )

set(CRYPTO_HEADERS
    dap_enc.h
    dap_enc_base64.h
    dap_enc_aes.h
    dap_enc_newhope.h
    dap_enc_msrln16.h
    dap_enc_key.h
    dap_enc_sidh16.h
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


include_directories("${dap_core_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${CRYPTO_HEADERS} )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
