
include (../net/client/libdap-net-client.pri)
include (../net/core/libdap-net-core.pri)
include (../net/server/libdap-net-server.pri)
include (../net/stream/libdap-net-stream.pri)

INCLUDEPATH += \
#            /usr/include/json-c \
#            /usr/include \
#            /usr/include/x86_64-linux-gnu/bits \
#            /usr/include/x86_64-linux-gnu \
            $$PWD/../net/server/http_server/http_client/include \
            $$PWD/../net/server/http_server/include \
            $$PWD/../net/server/enc_server/include \
            $$PWD/../net/server/notify_server/include \
            $$PWD/../net/server/json_rpc/include \
            $$PWD/../net/server/http_server \
            $$PWD/../net/stream/session/include \
            $$PWD/../net/stream/stream/include \
            $$PWD/../net/stream/ch/include \
            $$PWD/../core/src/unix


#INCLUDEPATH += $$PWD/include $$PWD/../ $$PWD/src $$PWD/src/XKCP/lib/high/Keccak/FIPS202 $$PWD/src/XKCP/lib/high/Keccak/SP800-185 $$PWD/src/XKCP/lib/high/common $$PWD/src/XKCP/lib/common
