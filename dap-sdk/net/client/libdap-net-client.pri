android{
    include (../../../3rdparty/json-c/json-c.pri)
}

HEADERS += $$PWD/include/dap_client.h \
    $$PWD/include/dap_client_http.h \
    $$PWD/include/dap_client_pool.h \
    $$PWD/include/dap_client_pvt.h

SOURCES += $$PWD/dap_client.c \
    $$PWD/dap_client_http.c \
    $$PWD/dap_client_pool.c \
    $$PWD/dap_client_pvt.c \
    $$PWD/dap_client_pvt_hh.c

INCLUDEPATH += $$PWD/include
