include(linux)

HEADERS += $$PWD/dap_cpu_monitor.h \
            $$PWD/dap_network_monitor.h \

SOURCES += $$PWD/dap_cpu_monitor.c \
           $$PWD/dap_network_monitor.c

INCLUDEPATH += $$PWD
