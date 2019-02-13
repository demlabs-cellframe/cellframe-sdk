linux-* {
    include(linux/linux.pri)
}

!android {

HEADERS += $$PWD/dap_cpu_monitor.h \
           $$PWD/dap_process_manager.h \
           $$PWD/dap_process_memory.h \

SOURCES += $$PWD/dap_cpu_monitor.c \
           $$PWD/dap_process_manager.c \
           $$PWD/dap_process_memory.c \

INCLUDEPATH += $$PWD

}
