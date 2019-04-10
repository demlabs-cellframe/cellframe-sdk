HEADERS += $$PWD/dap_http_client.h \
    $$PWD/dap_http_client_simple.h \
    $$PWD/dap_http_header.h


SOURCES += $$PWD/dap_http_client.c \
    $$PWD/dap_http_client_simple.c \
    $$PWD/dap_http_header.c


linux-* {
    LIBS += -lcurl
}

INCLUDEPATH += $$PWD
