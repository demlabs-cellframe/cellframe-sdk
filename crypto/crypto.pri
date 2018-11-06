HEADERS += $$PWD/dap_enc.h \
    $$PWD/dap_enc_base64.h \
    $$PWD/dap_enc_iaes.h \
    $$PWD/dap_enc_msrln.h \
    $$PWD/dap_enc_key.h \
    $$PWD/dap_enc_defeo.h \
    $$PWD/IAES/dap_iaes_proto.h \
    $$PWD/sha3/fips202.h \
    $$PWD/DeFeo_Scheme/config.h \
    $$PWD/DeFeo_Scheme/P768_internal.h \
    $$PWD/MSRLN/MSRLN.h \
    $$PWD/rand/dap_rand.h \

SOURCES += $$PWD/dap_enc.c \
    $$PWD/dap_enc_base64.c \
    $$PWD/dap_enc_iaes.c \
    $$PWD/dap_enc_msrln.c \
    $$PWD/dap_enc_key.c \
    $$PWD/dap_enc_defeo.c \
    $$PWD/IAES/iaes256_cbc_cernal.c \
    $$PWD/sha3/fips202.c \
    $$PWD/DeFeo_Scheme/defeo_kex.c \
    $$PWD/MSRLN/kex.c \
    $$PWD/MSRLN/ntt_constants.c \
    $$PWD/MSRLN/random.c \
    $$PWD/rand/dap_rand.c \


INCLUDEPATH += $$PWD
