cmake_minimum_required(VERSION 2.8)
project (dap_chain)
  
set(DAP_CHAIN_SRCS 
        dap_chain_common.c
        dap_chain_datum.c 
        dap_chain_datum_hashtree_roots.c
        dap_chain_datum_tx_items.c
        dap_chain_datum_tx.c
        dap_chain_datum_tx_token.c
        dap_chain_datum_token.c
        dap_chain_ledger.c
        dap_chain_datum_tx_out_cond.c
        dap_chain_pvt.c
        dap_chain.c
        dap_chain_cs.c
        dap_chain_cell.c
        )

set(DAP_CHAIN_HEADERS
        dap_chain.h
        dap_chain_pvt.h
        dap_chain_common.h
        dap_chain_datum.h
        dap_chain_datum_token.h
        dap_chain_datum_hashtree_roots.h
        dap_chain_datum_tx_items.h
        dap_chain_datum_tx.h
        dap_chain_datum_tx_in.h
        dap_chain_datum_tx_in_cond.h
        dap_chain_datum_tx_out.h
        dap_chain_datum_tx_out_cond.h
        dap_chain_datum_tx_pkey.h
        dap_chain_datum_tx_sig.h
        dap_chain_datum_tx_token.h
        dap_chain_cs.h
        dap_chain_cell.h
        dap_chain_ledger.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS} ${DAP_CHAIN_HEADERS})

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

target_link_libraries(dap_chain dap_core dap_chain_crypto dap_chain_mempool dap_chain_global_db ${GLIB_LDFLAGS})
target_include_directories(dap_chain INTERFACE . ${GLIB_INCLUDE_DIRS})


set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
