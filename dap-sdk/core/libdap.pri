QMAKE_CFLAGS_RELEASE += -std=gnu11
QMAKE_CFLAGS_DEBUG = -std=gnu11
-DDAP_DEBUG
QMAKE_CXXFLAGS +=  -std=c++11
unix {
    include(src/unix/unix.pri)
    DEFINES += DAP_OS_UNIX
}
android {
    DEFINES += DAP_OS_ANDROID
}

unix: !android {
    QMAKE_CFLAGS_DEBUG += -Wall -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing
    QMAKE_LFLAGS_DEBUG += -pg
    DEFINES += _GNU_SOURCE
    LIBS += -lrt
}
darwin {
    include(src/darwin/darwin.pri)
    DEFINES += DAP_OS_DARWIN
    LIBS -= -lrt
}

win32 {
    include(src/win32/win32.pri)
    LIBS += -lntdll -lpsapi -ljson-c -lmagic -lmqrt -lshlwapi -lregex -ltre -lintl -liconv -lbcrypt -lcrypt32 -lsecur32 -luser32 -lws2_32 -lole32
    include($$PWD/../../3rdparty/wepoll/wepoll.pri)
    DEFINES += DAP_OS_WINDOWS
}

# 3rd party
HEADERS += $$PWD/../../3rdparty/uthash/src/utlist.h \
           $$PWD/../../3rdparty/uthash/src/uthash.h

# Sources itself
HEADERS += $$PWD/include/dap_common.h \
    $$PWD/include/dap_binary_tree.h \
    $$PWD/include/dap_config.h \
    $$PWD/include/dap_math_ops.h \
    $$PWD/include/dap_math_ops.h \
    $$PWD/include/dap_file_utils.h \
    $$PWD/src/circular_buffer.h \
    $$PWD/include/dap_circular_buffer.h \
    $$PWD/include/dap_list.h \
    $$PWD/include/dap_module.h \
    $$PWD/include/dap_strfuncs.h \
    $$PWD/include/dap_string.h

SOURCES += $$PWD/src/dap_common.c \
    $$PWD/src/dap_binary_tree.c \
    $$PWD/src/dap_config.c \
    $$PWD/src/dap_file_utils.c \
    $$PWD/src/dap_circular_buffer.c \
    $$PWD/src/dap_list.c \
    $$PWD/src/dap_module.c \
    $$PWD/src/dap_strfuncs.c \
    $$PWD/src/dap_string.c

INCLUDEPATH += $$PWD/include \
    $$PWD/../../3rdparty/uthash/src/
