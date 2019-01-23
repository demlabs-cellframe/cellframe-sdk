HEADERS += $$PWD/hash.h \
    $$PWD/lowmc_constants.h \
    $$PWD/picnic.h \
    $$PWD/picnic_impl.h \
    $$PWD/picnic_types.h \
    $$PWD/platform.h

macos { HEADERS += $$PWD/macos_specific_endian.h }

SOURCES +=  $$PWD/hash.c \
    $$PWD/lowmc_constants.c \
    $$PWD/picnic.c \
    $$PWD/picnic_impl.c \
    $$PWD/picnic_types.c \

INCLUDEPATH += $$PWD
