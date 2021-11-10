cmake_minimum_required(VERSION 3.0)
project (dap_chain_net)
  

file(GLOB DAP_CHAIN_NET_SRCS *.c)

file(GLOB DAP_CHAIN_NET_HEADERS include/*.h)

#if (ANDROID)
#    set(DAP_CHAIN_NET_HEADERS ${DAP_CHAIN_NET_HEADERS}
#        android/ifaddrs-android.h
#    )
#endif()

set(IPUTILS_INCLUDE_DIRS
     ../../3rdparty/iputils/traceroute/
    )

if(LINUX)
  file(GLOB IPUTILS_SRCS ../../3rdparty/iputils/*.c ../../3rdparty/iputils/traceroute/*.c)
  file(GLOB IPUTILS_HEADERS ../../3rdparty/iputils/*.h ${IPUTILS_INCLUDE_DIRS}*.h)
endif()

if(WIN32)
  add_definitions ("-DUNDEBUG")
  add_definitions ("-DNDEBUG")
  add_definitions ("-DWIN32")
  add_definitions ("-D_WINDOWS")
  add_definitions ("-D__WINDOWS__")
  add_definitions ("-D_CRT_SECURE_NO_WARNINGS")
  add_definitions ("-D_POSIX")
  add_definitions ("-D_POSIX_")
  add_definitions ("-D_POSIX_THREAD_SAFE_FUNCTIONS")
  add_compile_definitions(_GNU_SOURCE)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRCS} ${DAP_CHAIN_NET_HEADERS} ${IPUTILS_SRCS} ${IPUTILS_HEADERS})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_server_core dap_notify_srv dap_stream_ch_chain dap_stream_ch_chain_net dap_stream_ch_chain_net_srv dap_chain dap_chain_wallet dap_chain_net_srv
                            dap_chain_mempool dap_chain_global_db dap_chain_cs_none)
endif()

if(LINUX)
    target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_notify_srv dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_stream_ch_chain_net_srv dap_chain
      dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db dap_chain_cs_none
      resolv )
elseif(BSD)
    target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_notify_srv dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_stream_ch_chain_net_srv dap_chain
      dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db dap_chain_cs_none )
endif()


target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

if (!WIN32)
    target_include_directories(${PROJECT_NAME} PUBLIC ${IPUTILS_INCLUDE_DIRS})
endif()

