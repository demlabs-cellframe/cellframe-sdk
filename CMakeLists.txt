cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_dag)
  
set(DAP_CHAIN_DAG_SRCS 
  dap_chain_cs_dag.c 
        dap_chain_cs_dag_event.c
        )

set(DAP_CHAIN_DAG_HEADERS
        dap_chain_cs_dag.h
        dap_chain_cs_dag_event.h
    )

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_SRCS} ${DAP_CHAIN_DAG_HEADERS})

target_link_libraries(dap_chain_cs_dag dap_core dap_crypto dap_chain dap_chain_net dap_chain_crypto dap_chain_global_db)
target_include_directories(dap_chain_cs_dag INTERFACE .)

