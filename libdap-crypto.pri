include (src/defeo_scheme/defeo.pri)
include (src/iaes/iaes.pri)
include (src/oaes/oaes.pri)
include (src/msrln/msrln.pri)
include (src/rand/rand.pri)
include (src/sha3/sha3.pri)
include (src/sig_bliss/sig_bliss.pri)
include (src/sig_picnic/sig_picnic.pri)
include (src/sig_tesla/sig_tesla.pri)

HEADERS += $$PWD/include/dap_enc.h \
    $$PWD/include/dap_enc_base64.h \
    $$PWD/include/dap_enc_iaes.h \
    $$PWD/include/dap_enc_oaes.h \
    $$PWD/include/dap_enc_msrln.h \
    $$PWD/include/dap_enc_key.h \
    $$PWD/include/dap_enc_defeo.h \
    $$PWD/include/dap_enc_picnic.h \
    $$PWD/include/dap_enc_bliss.h \
    $$PWD/include/dap_enc_tesla.h \
    $$PWD/include/dap_crypto_common.h \
    $$PWD/include/dap_enc_base58.h \
    $$PWD/include/dap_enc_ca.h

SOURCES += $$PWD/src/dap_enc.c \
    $$PWD/src/dap_enc_base64.c \
    $$PWD/src/dap_enc_iaes.c \
    $$PWD/src/dap_enc_oaes.c \
    $$PWD/src/dap_enc_msrln.c \
    $$PWD/src/dap_enc_key.c \
    $$PWD/src/dap_enc_defeo.c \
    $$PWD/src/dap_enc_picnic.c \
    $$PWD/src/dap_enc_bliss.c \
    $$PWD/src/dap_enc_tesla.c \
    $$PWD/src/dap_enc_base58.c \
    $$PWD/src/dap_enc_ca.c

INCLUDEPATH += $$PWD/include $$PWD/../ $$PWD/src
