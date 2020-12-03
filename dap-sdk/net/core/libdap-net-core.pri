HEADERS += $$PWD/include/dap_events.h \
    $$PWD/include/dap_events_socket.h \
    $$PWD/include/dap_net.h \
    $$PWD/include/dap_proc_queue.h \
    $$PWD/include/dap_proc_thread.h \
    $$PWD/include/dap_server.h \
    $$PWD/include/dap_timerfd.h \
    $$PWD/include/dap_worker.h 

SOURCES += $$PWD/dap_events.c \
    $$PWD/dap_events_socket.c \
    $$PWD/dap_net.c \
    $$PWD/dap_proc_queue.c \
    $$PWD/dap_proc_thread.c \
    $$PWD/dap_server.c \
    $$PWD/dap_timerfd.c \
    $$PWD/dap_worker.c 

INCLUDEPATH += $$PWD/include
