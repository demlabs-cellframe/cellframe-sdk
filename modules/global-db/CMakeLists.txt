cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)

file(GLOB DAP_CHAIN_GLOBAL_DB_SRC
    dap_chain_global_db_driver_cdb.c
    dap_chain_global_db_driver_sqlite.c
    dap_chain_global_db.c
    dap_chain_global_db_remote.c
    dap_chain_global_db_driver.c
    dap_chain_global_db_driver_pgsql.c
)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR
    include/dap_chain_global_db.h
    include/dap_chain_global_db_remote.h
    include/dap_chain_global_db_driver.h
    include/dap_chain_global_db_driver_pgsql.h
    include/dap_chain_global_db_driver_cdb.h
    include/dap_chain_global_db_driver_sqlite.h
)

set(DAP_CHAIN_GLOBAL_DB_LIBS dap_core dap_crypto dap_chain sqlite3 dap_cuttdb json-c)

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

target_link_libraries(${PROJECT_NAME}  ${DAP_CHAIN_GLOBAL_DB_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

