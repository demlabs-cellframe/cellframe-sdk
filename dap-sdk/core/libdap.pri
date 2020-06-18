QMAKE_CFLAGS_DEBUG = -std=gnu11
QMAKE_CFLAGS_RELEASE = -std=gnu11
unix {
    include(src/unix/unix.pri)
    DEFINES += DAP_OS_UNIX
}
unix: !android {
    LIBS += -lrt
}
darwin {
    include(src/darwin/darwin.pri)
    DEFINES += DAP_OS_DARWIN
    LIBS -= -lrt
}

win32 {
    include(src/win32/win32.pri)
    LIBS += -lpsapi
    DEFINES += DAP_OS_WINDOWS
}

HEADERS += $$PWD/include/dap_common.h \
    $$PWD/include/dap_binary_tree.h \
    $$PWD/include/dap_config.h \
    $$PWD/include/dap_math_ops.h \
    $$PWD/include/uthash.h \
    $$PWD/include/utlist.h \
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

INCLUDEPATH += $$PWD/include
