QMAKE_CFLAGS_DEBUG = -std=gnu11
QMAKE_CFLAGS_RELEASE = -std=gnu11

include (core/core.pri)
include (crypto/crypto.pri)

INCLUDEPATH += $$PWD
