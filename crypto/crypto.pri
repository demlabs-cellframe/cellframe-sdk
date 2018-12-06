include (defeo_scheme/defeo.pri)
include (iaes/iaes.pri)
include (oaes/oaes.pri)
include (msrln/msrln.pri)
include (rand/rand.pri)
include (sha3/sha3.pri)
include (sig_bliss/sig_bliss.pri)

HEADERS += $$PWD/dap_enc.h \
    $$PWD/dap_enc_base64.h \
    $$PWD/dap_enc_iaes.h \
    $$PWD/dap_enc_oaes.h \
    $$PWD/dap_enc_msrln.h \
    $$PWD/dap_enc_key.h \
    $$PWD/dap_enc_defeo.h \
    $$PWD/dap_enc_picnic.h \
    $$PWD/dap_enc_bliss.h \

SOURCES += $$PWD/dap_enc.c \
    $$PWD/dap_enc_base64.c \
    $$PWD/dap_enc_iaes.c \
    $$PWD/dap_enc_oaes.c \
    $$PWD/dap_enc_msrln.c \
    $$PWD/dap_enc_key.c \
    $$PWD/dap_enc_defeo.c \
    $$PWD/dap_enc_picnic.c \
    $$PWD/dap_enc_bliss.c \

INCLUDEPATH += $$PWD
