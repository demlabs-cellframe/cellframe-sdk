INCLUDEPATH += $$PWD

HEADERS += $$PWD/blowfish.h \
           $$PWD/bf_local.h \
           $$PWD/bf_pi.h

SOURCES += $$PWD/bf_cfb64.c \
           $$PWD/bf_ecb.c \
           $$PWD/bf_enc.c \
           $$PWD/bf_ofb64.c \
           $$PWD/bf_skey.c
