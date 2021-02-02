cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)
  
set(DAP_CHAIN_GLOBAL_DB_SRC
            dap_chain_global_db.c
            dap_chain_global_db_driver.c
            dap_chain_global_db_driver_cdb.c
            dap_chain_global_db_driver_sqlite.c
            dap_chain_global_db_hist.c
            dap_chain_global_db_remote.c
    )
set(DAP_CHAIN_GLOBAL_DB_HDR
        include/dap_chain_global_db.h
        include/dap_chain_global_db_driver.h
        include/dap_chain_global_db_driver_cdb.h
        include/dap_chain_global_db_driver_sqlite.h
        include/dap_chain_global_db_hist.h
        include/dap_chain_global_db_remote.h
    )
set(DAP_CHAIN_GLOBAL_DB_LIBS dap_core dap_crypto dap_chain sqlite3 dap_cuttdb json-c)

if(BUILD_WITH_GDB_DRIVER_MDBX)
    set(DAP_CHAIN_GLOBAL_DB_SRC ${DAP_CHAIN_GLOBAL_DB_SRC} dap_chain_global_db_driver_mdbx.c)
    set(DAP_CHAIN_GLOBAL_DB_HDR ${DAP_CHAIN_GLOBAL_DB_HDR} include/dap_chain_global_db_driver_mdbx.h)
    set(DAP_CHAIN_GLOBAL_DB_LIBS ${DAP_CHAIN_GLOBAL_DB_LIBS} mdbx-static)
    add_definitions ("-DDAP_CHAIN_GDB_ENGINE_MDBX")
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

target_link_libraries(${PROJECT_NAME}  ${DAP_CHAIN_GLOBAL_DB_LIBS})

target_include_directories(dap_chain_global_db INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

