#QMAKE_CFLAGS_RELEASE += -std=gnu11
#QMAKE_CFLAGS_DEBUG = -std=gnu11 -DDAP_DEBUG
#QMAKE_CFLAGS_RELEASE += -std=gnu1
QMAKE_CFLAGS_DEBUG += -DDAP_DEBUG
QMAKE_CXXFLAGS +=  -std=c++11
QMAKE_CFLAGS +=  -std=gnu11

unix {
    include(src/unix/unix.pri)
    DEFINES += DAP_OS_UNIX
}
android {
    DEFINES += DAP_OS_ANDROID DAP_OS_LINUX DAP_OS_UNIX
}

unix: !android : ! darwin {
    QMAKE_CFLAGS_DEBUG += -Wall -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing
    QMAKE_LFLAGS_DEBUG += -pg
    DEFINES += _GNU_SOURCE
    LIBS += -lrt -ljson-c -lmagic
}

contains(DAP_FEATURES, ssl){
    include($$PWD/../../3rdparty/wolfssl/wolfssl.pri)
}else{
    DEFINES += DAP_NET_CLIENT_NO_SSL
}

darwin {
    QMAKE_CFLAGS_DEBUG += -Wall -g3 -ggdb -fno-strict-aliasing
    DEFINES += _GNU_SOURCE
    include(src/darwin/darwin.pri)
    DEFINES += DAP_OS_DARWIN DAP_OS_BSD
    LIBS+ = -lrt
    #-ljson-c -lmagic
    QMAKE_LIBDIR += /usr/local/lib
    QMAKE_CFLAGS += -Wno-deprecated-copy -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable
    QMAKE_CXXFLAGS += -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable

    QMAKE_CFLAGS_DEBUG += -gdwarf-2
    QMAKE_CXXFLAGS_DEBUG += -gdwarf-2
}

win32 {
    include(src/win32/win32.pri)
    LIBS += -lntdll -lpsapi -ljson-c -lmagic -lmqrt -lshlwapi -lregex -ltre -lintl -liconv -lbcrypt -lcrypt32 -lsecur32 -luser32 -lws2_32 -lole32
    include($$PWD/../../3rdparty/wepoll/wepoll.pri)
    DEFINES += DAP_OS_WINDOWS
    QMAKE_CFLAGS_DEBUG += -Wall -ggdb -g3
}

# 3rd party
HEADERS += $$PWD/../../3rdparty/uthash/src/utlist.h \
           $$PWD/../../3rdparty/uthash/src/uthash.h

#if(DAPSDK_MODULES MATCHES "ssl-support")
#    include($$PWD/../../3rdparty/wolfssl/wolfssl.pri)
#endif()

# Sources itself
HEADERS += $$PWD/include/dap_common.h \
    $$PWD/include/dap_binary_tree.h \
    $$PWD/include/dap_config.h \
    $$PWD/include/dap_math_ops.h \
    $$PWD/include/dap_file_utils.h \
    $$PWD/include/dap_cbuf.h \
    $$PWD/include/dap_list.h \
    $$PWD/include/dap_module.h \
    $$PWD/include/dap_strfuncs.h \
    $$PWD/include/dap_string.h \
    $$PWD/include/dap_time.h \
    $$PWD/include/dap_tsd.h \
    $$PWD/include/dap_fnmatch.h \
    $$PWD/include/dap_fnmatch_loop.h \
    $$PWD/include/portable_endian.h

SOURCES += $$PWD/src/dap_common.c \
    $$PWD/src/dap_binary_tree.c \
    $$PWD/src/dap_config.c \
    $$PWD/src/dap_file_utils.c \
    $$PWD/src/dap_cbuf.c \
    $$PWD/src/dap_list.c \
    $$PWD/src/dap_module.c \
    $$PWD/src/dap_strfuncs.c \
    $$PWD/src/dap_string.c \
    $$PWD/src/dap_time.c \
    $$PWD/src/dap_tsd.c \
    $$PWD/src/dap_fnmatch.c 






INCLUDEPATH += $$PWD/include \
    $$PWD/../../3rdparty/uthash/src/
