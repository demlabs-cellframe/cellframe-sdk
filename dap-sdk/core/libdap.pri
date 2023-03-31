#QMAKE_CFLAGS_RELEASE += -std=gnu11
#QMAKE_CFLAGS_DEBUG = -std=gnu11 -DDAP_DEBUG
#QMAKE_CFLAGS_RELEASE += -std=gnu1
QMAKE_CFLAGS_DEBUG += -DDAP_DEBUG
QMAKE_CXXFLAGS +=  -std=c++11
QMAKE_CFLAGS +=  -std=gnu11

unix {
    #include(src/unix/unix.pri)
    DEFINES += DAP_OS_UNIX DAP_OS_LINUX
}
android {
    DEFINES += DAP_OS_ANDROID DAP_OS_LINUX DAP_OS_UNIX
}

unix: !android : ! darwin {
    #QMAKE_CFLAGS_DEBUG += -Wall -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing
    #QMAKE_LFLAGS_DEBUG += -pg
    DEFINES += _GNU_SOURCE
    LIBS += -lrt -lmagic
}

#contains(DAP_FEATURES, ssl){
#    include($$PWD/../../3rdparty/wolfssl/wolfssl.pri)
#}else{
    DEFINES += DAP_NET_CLIENT_NO_SSL
#}

darwin {
    QMAKE_CFLAGS_DEBUG += -Wall -g3 -ggdb -fno-strict-aliasing
    DEFINES += _GNU_SOURCE
    include(src/darwin/darwin.pri)
    DEFINES += DAP_OS_DARWIN DAP_OS_BSD
    LIBS+ = -lrt

    QMAKE_LIBDIR += /usr/local/lib
    QMAKE_CFLAGS += -Wno-deprecated-copy -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable
    QMAKE_CXXFLAGS += -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable

    QMAKE_CFLAGS_DEBUG += -gdwarf-2
    QMAKE_CXXFLAGS_DEBUG += -gdwarf-2
}

win32 {
    include(src/win32/win32.pri)
    LIBS += -lntdll -lpsapi  -lmagic -lmqrt -lshlwapi -lregex -ltre -lintl -liconv -lbcrypt -lcrypt32 -lsecur32 -luser32 -lws2_32 -lole32
    include($$PWD/../../3rdparty/wepoll/wepoll.pri)
    DEFINES += DAP_OS_WINDOWS
    QMAKE_CFLAGS_DEBUG += -Wall -ggdb -g3
}
