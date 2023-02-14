INCLUDEPATH += $$PWD

HEADERS += \
    $$PWD/config.h \
    $$PWD/falcon.h \
    $$PWD/falcon_params.h \
    $$PWD/fpr.h \
    $$PWD/inner.h

SOURCES += \
    $$PWD/codec.c \
    $$PWD/common.c \
    $$PWD/falcon.c \
    $$PWD/fft.c \
    $$PWD/fpr.c \
    $$PWD/keygen.c \
    $$PWD/rng.c \
    $$PWD/shake.c \
    $$PWD/falcon_sign.c \
    #$$PWD/speed.c \
    $$PWD/vrfy.c
