include (src/defeo_scheme/defeo.pri)
include (src/iaes/iaes.pri)
include (src/oaes/oaes.pri)
include (src/GOST/GOST.pri)
include (src/salsa2012/salsa2012.pri)
include (src/blowfish/blowfish.pri)
include (src/msrln/msrln.pri)
include (src/rand/rand.pri)
include (src/sha3/sha3.pri)
include (src/sig_bliss/sig_bliss.pri)
include (src/sig_picnic/sig_picnic.pri)
include (src/sig_tesla/sig_tesla.pri)
include (src/sig_dilithium/sig_dilithium.pri)
include (src/ringct20/ringct20.pri)
include (src/seed/seed.pri)
include (src/newhope/newhope.pri)

DEFINES += KeccakP1600timesN_excluded

HEADERS += $$PWD/src/XKCP/lib/common/config.h \
    $$PWD/include/dap_enc.h \
    $$PWD/include/dap_enc_base64.h \
    $$PWD/include/dap_enc_iaes.h \
    $$PWD/include/dap_enc_oaes.h \
    $$PWD/include/dap_enc_bf.h \
    $$PWD/include/dap_enc_GOST.h \
    $$PWD/include/dap_enc_msrln.h \
    $$PWD/include/dap_enc_key.h \
    $$PWD/include/dap_enc_defeo.h \
    $$PWD/include/dap_enc_picnic.h \
    $$PWD/include/dap_enc_bliss.h \
    $$PWD/include/dap_enc_tesla.h \
    $$PWD/include/dap_enc_base58.h \
    $$PWD/include/dap_enc_dilithium.h \
    $$PWD/include/dap_enc_ringct20.h \
    $$PWD/include/dap_enc_salsa2012.h \
    $$PWD/include/dap_enc_SEED.h \
    $$PWD/include/dap_enc_newhope.h \
    $$PWD/include/dap_crypto_common.h \
    $$PWD/include/dap_cert.h \
    $$PWD/include/dap_cert_file.h \
    $$PWD/include/dap_pkey.h \
    $$PWD/include/dap_sign.h \
    $$PWD/include/dap_uuid.h \
    $$PWD/include/dap_hash.h \
    $$PWD/include/dap_hash_fusion.h \
    $$PWD/include/dap_hash_keccak.h \
    $$PWD/src/XKCP/lib/high/Keccak/FIPS202/SimpleFIPS202.h \
    $$PWD/src/XKCP/lib/high/Keccak/SP800-185/SP800-185.h \
    $$PWD/src/XKCP/lib/high/common/Phases.h

SOURCES += $$PWD/src/dap_enc.c \
    $$PWD/src/dap_enc_base64.c \
    $$PWD/src/dap_enc_iaes.c \
    $$PWD/src/dap_enc_oaes.c \
    $$PWD/src/dap_enc_bf.c \
    $$PWD/src/dap_enc_GOST.c \
    $$PWD/src/dap_enc_msrln.c \
    $$PWD/src/dap_enc_key.c \
    $$PWD/src/dap_enc_defeo.c \
    $$PWD/src/dap_enc_picnic.c \
    $$PWD/src/dap_enc_bliss.c \
    $$PWD/src/dap_enc_tesla.c \
    $$PWD/src/dap_enc_base58.c \
    $$PWD/src/dap_enc_dilithium.c \
    $$PWD/src/dap_enc_ringct20.c \
    $$PWD/src/dap_enc_salsa2012.c \
    $$PWD/src/dap_enc_ca.c \
    $$PWD/src/dap_cert.c \
    $$PWD/src/dap_cert_file.c \
    $$PWD/src/dap_pkey.c \
    $$PWD/src/dap_sign.c \
    $$PWD/src/dap_hash.c \
    $$PWD/src/dap_uuid.c \
    $$PWD/src/dap_hash_fusion.c \
    $$PWD/src/dap_hash_keccak.c \
    $$PWD/src/dap_enc_SEED.c \
    $$PWD/src/dap_enc_newhope.c \
    $$PWD/src/XKCP/lib/high/Keccak/FIPS202/SimpleFIPS202.c \
    $$PWD/src/XKCP/lib/high/Keccak/SP800-185/SP800-185.c \
    $$PWD/src/XKCP/lib/high/Keccak/SP800-185/SP800-185.inc


INCLUDEPATH += $$PWD/include $$PWD/../ $$PWD/src $$PWD/src/XKCP/lib/high/Keccak/FIPS202 $$PWD/src/XKCP/lib/high/Keccak/SP800-185 $$PWD/src/XKCP/lib/high/common $$PWD/src/XKCP/lib/common
