unix {
    include(unix/unix.pri)
    LIBS += -lrt
}
darwin {
    include(darwin/darwin.pri)
}

HEADERS += $$PWD/dap_common.h \
    $$PWD/dap_config.h \
    $$PWD/dap_math_ops.h \
    $$PWD/uthash.h \
    $$PWD/utlist.h \
    $$PWD/dap_math_ops.h \
    $$PWD/dap_file_utils.h \
    $$PWD/circular_buffer.h \
    $$PWD/dap_circular_buffer.h \
    $$PWD/dap_list.h \
    $$PWD/dap_module.h \
    $$PWD/dap_strfuncs.h \
    $$PWD/dap_string.h

SOURCES += $$PWD/dap_common.c \
    $$PWD/dap_config.c \
    $$PWD/dap_file_utils.c \
    $$PWD/dap_circular_buffer.c \
    $$PWD/dap_list.c \
    $$PWD/dap_module.c \
    $$PWD/dap_strfuncs.c \
    $$PWD/dap_string.c

INCLUDEPATH += $$PWD
