cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)

file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR include/*.h)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/cuttdb ${CMAKE_CURRENT_BINARY_DIR}/../../3rdparty/cuttdb)
if (BUILD_WITH_GDB_DRIVER_MDBX)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/libmdbx ${CMAKE_CURRENT_BINARY_DIR}/../../3rdparty/libmdbx EXCLUDE_FROM_ALL)
endif()

set(DAP_CHAIN_GLOBAL_DB_LIBS dap_core dap_io dap_crypto dap_chain dap_chain_net sqlite3 dap_cuttdb json-c)

if(BUILD_WITH_GDB_DRIVER_MDBX)
    file(GLOB DAP_CHAIN_GLOBAL_DB_SRC ${DAP_CHAIN_GLOBAL_DB_SRC} dap_chain_global_db_driver_mdbx.c)
    file(GLOB DAP_CHAIN_GLOBAL_DB_HRR ${DAP_CHAIN_GLOBAL_DB_HDR} include/dap_chain_global_db_driver_mdbx.h)

    set(DAP_CHAIN_GLOBAL_DB_LIBS ${DAP_CHAIN_GLOBAL_DB_LIBS} mdbx-static)
    add_definitions ("-DDAP_CHAIN_GDB_ENGINE_MDBX")
endif()

if(BUILD_WITH_GDB_DRIVER_PGSQL)
    set(DAP_CHAIN_GLOBAL_DB_LIBS ${DAP_CHAIN_GLOBAL_DB_LIBS} pq)
    add_definitions ("-DDAP_CHAIN_GDB_ENGINE_PGSQL")
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

target_link_libraries(${PROJECT_NAME} ${DAP_CHAIN_GLOBAL_DB_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

