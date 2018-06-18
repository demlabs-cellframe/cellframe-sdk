HEADERS += $$PWD/dap_enc.h \
    $$PWD/dap_enc_base64.h \
    $$PWD/dap_enc_aes.h \
    $$PWD/dap_enc_newhope.h \
    $$PWD/dap_enc_msrln16.h \
    $$PWD/dap_enc_key.h \
    $$PWD/dap_enc_sidh16.h \
    $$PWD/liboqs/kex_sidh_cln16/kex_sidh_cln16.h \
    $$PWD/liboqs/kex_sidh_cln16/SIDH.h \
    $$PWD/liboqs/kex_sidh_cln16/SIDH_internal.h \
    $$PWD/liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h \
    $$PWD/liboqs/kex_rlwe_msrln16/LatticeCrypto_priv.h \
    $$PWD/liboqs/kex_rlwe_msrln16/LatticeCrypto.h \
    $$PWD/liboqs/crypto/sha3/sha3.h \
    $$PWD/liboqs/crypto/rand/rand.h \
    $$PWD/liboqs/crypto/rand_urandom_aesctr/rand_urandom_aesctr.h \
    $$PWD/liboqs/crypto/rand_urandom_chacha20/rand_urandom_chacha20.h \
    $$PWD/liboqs/crypto/aes/aes_local.h \
    $$PWD/liboqs/crypto/aes/aes.h

SOURCES += $$PWD/dap_enc.c \
    $$PWD/dap_enc_base64.c \
    $$PWD/dap_enc_aes.c \
    $$PWD/dap_enc_newhope.c \
    $$PWD/dap_enc_msrln16.c \
    $$PWD/dap_enc_key.c \
    $$PWD/dap_enc_sidh16.c \
    $$PWD/liboqs/kex_sidh_cln16/kex_sidh_cln16.c \
    $$PWD/liboqs/kex_sidh_cln16/SIDH.c \
    $$PWD/liboqs/kex_sidh_cln16/SIDH_setup.c \
    $$PWD/liboqs/kex_sidh_cln16/sidh_kex.c \
    $$PWD/liboqs/kex_sidh_cln16/ec_isogeny.c \
    $$PWD/liboqs/kex_sidh_cln16/fpx.c \
    $$PWD/liboqs/kex_sidh_cln16/generic/fp_generic.c \
    $$PWD/liboqs/kex_rlwe_msrln16/generic/ntt.c \
    $$PWD/liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.c \
    $$PWD/liboqs/kex_rlwe_msrln16/LatticeCrypto_kex.c \
    $$PWD/liboqs/kex_rlwe_msrln16/ntt_constants.c \
    $$PWD/liboqs/crypto/sha3/sha3.c \
    $$PWD/liboqs/crypto/rand/rand.c \
    $$PWD/liboqs/crypto/rand_urandom_aesctr/rand_urandom_aesctr.c \
    $$PWD/liboqs/crypto/rand_urandom_chacha20/rand_urandom_chacha20.c \
    $$PWD/liboqs/crypto/aes/aes_c.c \
    $$PWD/liboqs/crypto/aes/aes_ni.c \
    $$PWD/liboqs/crypto/aes/aes.c 



INCLUDEPATH += $$PWD
