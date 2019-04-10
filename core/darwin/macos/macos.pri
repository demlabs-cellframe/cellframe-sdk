HEADERS += $$PWD/dap_network_monitor.h \
HEADERS += $$PWD/pthread_barrier.h

SOURCES += $$PWD/dap_network_monitor.c

INCLUDEPATH += $$PWD

LIBS += -framework CoreFoundation
LIBS += -framework SystemConfiguration
#LIBS += -framework NetworkExtension
