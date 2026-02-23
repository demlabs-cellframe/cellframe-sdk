cmake_minimum_required(VERSION 3.10)
project (dap_chain_net)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)
  

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
    set_source_files_properties(../../3rdparty/iputils/traceroute/clif.c PROPERTIES COMPILE_FLAGS -Wno-stringop-truncation)
endif()

if(WIN32)
  # Will be set after create_object_library
  set(WIN32_DEFINITIONS _GNU_SOURCE)
endif()

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_NET_SRCS} ${IPUTILS_SRCS} HEADERS ${DAP_CHAIN_NET_HEADERS} ${IPUTILS_HEADERS})

if(WIN32)
  target_compile_definitions(${PROJECT_NAME} PUBLIC ${WIN32_DEFINITIONS})
endif()

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_client dap_io dap_notify_srv dap_cli_server dap_chain dap_chain_wallet
                                        dap_chain_net_srv dap_chain_net_srv_voting dap_chain_mempool dap_global_db dap_chain_net_srv_xchange dap_chain_cs_none
                                        dap_stream_ch_chain_net dap_chain_cs_esbocs dap_json_rpc )
if(LINUX)
    # resolv is a system library, will be linked at final stage
    # Store for later linking
    target_link_libraries(${PROJECT_NAME} INTERFACE resolv)
endif()

target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/uthash/src)

if (!WIN32)
    target_include_directories(${PROJECT_NAME} PUBLIC ${IPUTILS_INCLUDE_DIRS})
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/
        ARCHIVE DESTINATION lib/modules/net/
        PUBLIC_HEADER DESTINATION include/modules/net/
)
endif()
