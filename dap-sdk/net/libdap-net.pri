DEFINES += _GNU_SOURCE

HEADERS += $$PWD/client/include/*.h \
    $$PWD/core/include/*.h \
    $$PWD/server/enc_server/include/*.h \
    $$PWD/server/http_server/include/*.h \
    $$PWD/server/http_server/http_client/include/*.h \
    $$PWD/server/json_rpc/include/*.h \
    $$PWD/stream/ch/include/*.h \
    $$PWD/stream/session/include/*.h \
    $$PWD/stream/stream/include/*.h \


SOURCES += $$PWD/client/*.c \
    $$PWD/core/*.c \
    $$PWD/server/enc_server/*.c \
    $$PWD/server/http_server/*.c \
    $$PWD/server/http_server/http_client/*.c \
    $$PWD/server/json_rpc/src/*.c \
    $$PWD/stream/ch/*.c \
    $$PWD/stream/session/*.c \
    $$PWD/stream/stream/*.c \

INCLUDEPATH += $$PWD/client/include $$PWD/core/include $$PWD/server/enc_server/include $$PWD/server/http_server/include \
               $$PWD/server/http_server $$PWD/server/http_server/http_client/include $$PWD/server/json_rpc/include $$PWD/stream/ch/include \
               $$PWD/stream/session/include $$PWD/stream/stream/include

LIBS += -ljson-c -lmagic
