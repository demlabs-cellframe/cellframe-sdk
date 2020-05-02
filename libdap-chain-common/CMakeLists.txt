cmake_minimum_required(VERSION 2.8)
project (dap_chain_common)
  
set(DAP_CHAIN_COMMON_SRCS 
        src/dap_chain_common.c
        src/dap_chain_datum.c
        src/dap_chain_datum_token.c
        src/dap_chain_datum_hashtree_roots.c
        src/dap_chain_datum_tx_items.c
        src/dap_chain_datum_tx.c
        src/dap_chain_datum_tx_out_cond.c
        src/dap_chain_datum_tx_token.c
        src/dap_chain_datum_tx_receipt.c
        )

set(DAP_CHAIN_COMMON_HEADERS
        include/dap_chain_common.h
        include/dap_chain_datum.h
        include/dap_chain_datum_token.h
        include/dap_chain_datum_hashtree_roots.h
        include/dap_chain_datum_tx_items.h
        include/dap_chain_datum_tx.h
        include/dap_chain_datum_tx_in.h
        include/dap_chain_datum_tx_in_cond.h
        include/dap_chain_datum_tx_out.h
        include/dap_chain_datum_tx_out_cond.h
        include/dap_chain_datum_tx_pkey.h
        include/dap_chain_datum_tx_sig.h
        include/dap_chain_datum_tx_token.h
        include/dap_chain_datum_tx_receipt.h
    )


add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_COMMON_SRCS} ${DAP_CHAIN_COMMON_HEADERS})

target_link_libraries(dap_chain_common dap_core dap_crypto )
target_include_directories(dap_chain_common PUBLIC include/ )
