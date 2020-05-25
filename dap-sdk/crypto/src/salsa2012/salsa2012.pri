INCLUDEPATH += $$PWD

HEADERS += $$PWD/common_salsa.h \
           $$PWD/crypto_core_salsa2012.h \
           $$PWD/crypto_stream_salsa2012.h \

SOURCES += $$PWD/core_salsa_ref.c \
           $$PWD/stream_salsa2012.c \
           $$PWD/stream_salsa2012_ref.c
