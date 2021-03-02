HEADERS += $$PWD/dap_network_monitor.h \
HEADERS += $$PWD/pthread_barrier.h

SOURCES += $$PWD/dap_network_monitor.c

INCLUDEPATH += $$PWD /usr/local/include

LIBS += -framework CoreFoundation
LIBS += -framework SystemConfiguration
#LIBS += -framework NetworkExtension
