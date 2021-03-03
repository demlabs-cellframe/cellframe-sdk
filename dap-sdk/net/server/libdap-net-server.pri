
android {
    include (../../../3rdparty/libmagic/file/libmagic.pri)
}

#enc_server
HEADERS += $$PWD/enc_server/include/dap_enc_http.h \
    $$PWD/enc_server/include/dap_enc_ks.h

SOURCES += $$PWD/enc_server/dap_enc_http.c \
    $$PWD/enc_server/dap_enc_ks.c
    
#http_server    
HEADERS += $$PWD/http_server/include/dap_http.h \
    $$PWD/http_server/include/dap_http_cache.h \
    $$PWD/http_server/include/dap_http_folder.h \
    $$PWD/http_server/include/http_status_code.h \
    $$PWD/http_server/include/dap_http_simple.h

SOURCES += $$PWD/http_server/dap_http.c \
    $$PWD/http_server/dap_http_cache.c \
    $$PWD/http_server/dap_http_folder.c \
    $$PWD/http_server/dap_http_simple.c

# notify server
#notify_server
HEADERS += $$PWD/notify_server/include/dap_notify_srv.h
SOURCES += $$PWD/notify_server/src/dap_notify_srv.c

include (../server/http_server/http_client/http.pri)
    
    
#json_rpc    
HEADERS += $$PWD/json_rpc/include/dap_json_rpc.h \
    $$PWD/json_rpc/include/dap_json_rpc_errors.h \
    $$PWD/json_rpc/include/dap_json_rpc_notification.h \
    $$PWD/json_rpc/include/dap_json_rpc_params.h \
    $$PWD/json_rpc/include/dap_json_rpc_request.h \
    $$PWD/json_rpc/include/dap_json_rpc_request_handler.h \
    $$PWD/json_rpc/include/dap_json_rpc_response.h \
    $$PWD/json_rpc/include/dap_json_rpc_response_handler.h

SOURCES += $$PWD/json_rpc/src/dap_json_rpc.c \
    $$PWD/json_rpc/src/dap_json_rpc_errors.c \
    $$PWD/json_rpc/src/dap_json_rpc_notification.c \
    $$PWD/json_rpc/src/dap_json_rpc_params.c \
    $$PWD/json_rpc/src/dap_json_rpc_request.c \
    $$PWD/json_rpc/src/dap_json_rpc_request_handler.c \
    $$PWD/json_rpc/src/dap_json_rpc_response.c \
    $$PWD/json_rpc/src/dap_json_rpc_response_handler.c
    
INCLUDEPATH += $$PWD/include
darwin{
    LIBS += -ljson-c -lmagic
}
