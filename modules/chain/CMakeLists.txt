cmake_minimum_required(VERSION 3.10)
project (dap_chain)
  
file(GLOB DAP_CHAIN_SRCS *.c)

file(GLOB DAP_CHAIN_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS} ${DAP_CHAIN_HEADERS})

#find_package(PkgConfig REQUIRED)
#pkg_search_module(GLIB REQUIRED glib-2.0)

target_link_libraries(dap_chain dap_core dap_chain_common dap_chain_mempool dap_chain_global_db ${GLIB_LDFLAGS})
target_include_directories(dap_chain INTERFACE . include/ ${GLIB_INCLUDE_DIRS})
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)
