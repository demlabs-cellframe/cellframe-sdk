#ch
HEADERS += $$PWD/ch/include/dap_stream_ch.h \
    $$PWD/ch/include/dap_stream_ch_pkt.h \
    $$PWD/ch/include/dap_stream_ch_proc.h

SOURCES += $$PWD/ch/dap_stream_ch.c \
    $$PWD/ch/dap_stream_ch_pkt.c \
    $$PWD/ch/dap_stream_ch_proc.c
    
#session
HEADERS += $$PWD/session/include/dap_stream_session.h

SOURCES += $$PWD/session/dap_stream_session.c
    
#stream
HEADERS += $$PWD/stream/include/dap_stream.h \
    $$PWD/stream/include/dap_stream_ctl.h \
    $$PWD/stream/include/dap_stream_pkt.h \
    $$PWD/stream/include/dap_stream_worker.h

SOURCES += $$PWD/stream/dap_stream.c \
    $$PWD/stream/dap_stream_ctl.c \
    $$PWD/stream/dap_stream_pkt.c \
    $$PWD/stream/dap_stream_worker.c


INCLUDEPATH += $$PWD/include
