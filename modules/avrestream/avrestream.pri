QMAKE_CFLAGS_DEBUG  += -DDAP_DEBUG
QMAKE_CFLAGS        += -std=gnu11




unix {
    ##include($$PWD/cellframe-sdk/dap-sdk/core/src/unix/unix.pri)
    DEFINES += DAP_OS_UNIX
}

android {
    DEFINES += DAP_OS_ANDROID DAP_OS_LINUX DAP_OS_UNIX
}

unix: !android : ! darwin {
    QMAKE_CFLAGS_DEBUG += -Wall -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function
    QMAKE_CFLAGS_DEBUG += -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable
    QMAKE_CFLAGS_DEBUG += -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing
    QMAKE_LFLAGS_DEBUG += -pg
    DEFINES += _GNU_SOURCE
    LIBS += -lrt
}

contains(DAP_FEATURES, ssl){
    include($$PWD/../../3rdparty/wolfssl/wolfssl.pri)
} else {
    DEFINES += DAP_NET_CLIENT_NO_SSL
}

darwin {
    QMAKE_CFLAGS_DEBUG += -Wall -g3 -ggdb -fno-strict-aliasing
    DEFINES += _GNU_SOURCE
    include(src/darwin/darwin.pri)
    DEFINES += DAP_OS_DARWIN DAP_OS_BSD
    LIBS+ = -lrt

    QMAKE_LIBDIR += /usr/local/lib
    QMAKE_CFLAGS += -Wno-deprecated-copy -Wno-deprecated-declarations -Wno-unused-local-typedefs
    QMAKE_CFLAGS += -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable
    QMAKE_CFLAGS += -Wno-unused-parameter -Wno-unused-but-set-variable

    QMAKE_CFLAGS_DEBUG += -gdwarf-2
}

win32 {
    include(src/win32/win32.pri)
    LIBS += -lntdll -lpsapi -ljson-c -lmagic -lmqrt -lshlwapi -lregex -ltre -lintl -liconv -lbcrypt -lcrypt32 -lsecur32 -luser32 -lws2_32 -lole32
    include($$PWD/../cellframe-node/cellframe-sdk/3rdparty/wepoll/wepoll.pri)
    DEFINES += DAP_OS_WINDOWS
    QMAKE_CFLAGS_DEBUG += -Wall -ggdb -g3
}


SDK_ROOT    = $$PWD/../..
DAP_SDK_ROOT    = $$PWD/../../../dap-sdk/

# 3rd party
HEADERS     += $$DAP_SDK_ROOT/3rdparty/uthash/src/utlist.h \
           $$DAP_SDK_ROOT/3rdparty/uthash/src/uthash.h


LIBS    += -lgstapp-1.0 -lgstbase-1.0 -lgstreamer-1.0 -lgobject-2.0 -lglib-2.0

INCLUDEPATH += $$PWD/include \
    $$DAP_SDK_ROOT/3rdparty/uthash/src/ \
    $$SDK_ROOT/dap-sdk/core/include/ \
    $$SDK_ROOT/dap-sdk/crypto/include/ \
    $$SDK_ROOT/dap-sdk/net/server/cli_server/include/ \
    $$SDK_ROOT/dap-sdk/io/include/ \
    $$SDK_ROOT/dap-sdk/core/src/unix/ \
    $$SDK_ROOT/dap-sdk/net/stream/ch/include/ \
    $$SDK_ROOT/dap-sdk/net/stream/stream/include/ \
    $$SDK_ROOT/dap-sdk/net/server/http_server/http_client/include/ \
    $$SDK_ROOT/dap-sdk/net/client/include/ \
    $$SDK_ROOT/dap-sdk/crypto/src/ \
    $$SDK_ROOT/dap-sdk/global-db/include/ \
    $$SDK_ROOT/modules/common/include/ \
    $$SDK_ROOT/modules/net/srv/include/ \
    $$SDK_ROOT/modules/net/include/ \
    $$SDK_ROOT/modules/global-db/include/ \
    $$SDK_ROOT/modules/chain/include/ \
    $$SDK_ROOT/modules/wallet/include/ \
    /usr/include/glib-2.0/ \
    /usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
    /usr/include/gstreamer-1.0/ \

# Sources itself
HEADERS += $$PWD/include/avrestream.h	\
    $$PWD/include/avrs_ch_cluster.h  \
    $$PWD/include/avrs_ch_pkt.h  \
    $$PWD/include/avrs_cli.h  \
    $$PWD/include/avrs_content.h \
    $$PWD/include/avrs_route.h  \
    $$PWD/include/avrs_srv.h \
    $$PWD/include/avrs_balancer.h  \
    $$PWD/include/avrs_ch.h \
    $$PWD/include/avrs_ch_session.h  \
    $$PWD/include/avrs_cluster.h  \
    $$PWD/include/avrs.h	 \
    $$PWD/include/avrs_session.h

SOURCES += $$PWD/avrestream.c \
    $$PWD/avrs.c \
    $$PWD/avrs_ch_cluster.c \
    $$PWD/avrs_ch_session.c \
    $$PWD/avrs_cluster.c \
    $$PWD/avrs_route.c	\
    $$PWD/avrs_srv.c \
    $$PWD/avrs_balancer.c \
    $$PWD/avrs_ch.c \
    $$PWD/avrs_ch_pkt.c  \
    $$PWD/avrs_cli.c \
    $$PWD/avrs_content.c \
    $$PWD/avrs_session.c

LIBS    += -lgstapp-1.0 -lgstbase-1.0 -lgstreamer-1.0 -lgobject-2.0 -lglib-2.0
