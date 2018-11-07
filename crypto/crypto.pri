HEADERS += $$PWD/dap_enc.h \
    $$PWD/dap_enc_base64.h \
    $$PWD/dap_enc_iaes.h \
    $$PWD/dap_enc_msrln.h \
    $$PWD/dap_enc_key.h \
    $$PWD/dap_enc_defeo.h \
    $$PWD/iaes/dap_iaes_proto.h \
    $$PWD/sha3/fips202.h \
    $$PWD/defeo_scheme/config.h \
    $$PWD/defeo_scheme/dap_P768_internal.h \
    $$PWD/msrln/msrln.h \
    $$PWD/rand/dap_rand.h \

SOURCES += $$PWD/dap_enc.c \
    $$PWD/dap_enc_base64.c \
    $$PWD/dap_enc_iaes.c \
    $$PWD/dap_enc_msrln.c \
    $$PWD/dap_enc_key.c \
    $$PWD/dap_enc_defeo.c \
    $$PWD/iaes/iaes256_cbc_cernal.c \
    $$PWD/sha3/fips202.c \
    $$PWD/defeo_scheme/defeo_kex.c \
    $$PWD/msrln/kex.c \
    $$PWD/msrln/random.c \
    $$PWD/rand/dap_rand.c \


INCLUDEPATH += $$PWD
