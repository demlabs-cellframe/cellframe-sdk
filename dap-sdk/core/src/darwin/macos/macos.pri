HEADERS += $$PWD/dap_network_monitor.h \
            $$PWD/dap_hw.h
HEADERS += $$PWD/pthread_barrier.h

SOURCES += $$PWD/dap_network_monitor.c \
            $$PWD/dap_hw.c

INCLUDEPATH += $$PWD

LIBS += -framework CoreFoundation
LIBS += -framework SystemConfiguration
#LIBS += -framework NetworkExtension
