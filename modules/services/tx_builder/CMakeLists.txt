cmake_minimum_required(VERSION 3.10)

project(dap_chain_tx_builder)

file(GLOB TX_BUILDER_SRCS *.c)
file(GLOB TX_BUILDER_HEADERS include/*.h)

# TX Builder - service layer (uses UTXO from ledger)
cellframe_add_library(${PROJECT_NAME} ${TX_BUILDER_SRCS} HEADERS ${TX_BUILDER_HEADERS})

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_datum      # For TX structures
    dap_chain_ledger     # For UTXO queries
)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${TX_BUILDER_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/services/tx_builder/
        ARCHIVE DESTINATION lib/modules/services/tx_builder/
        PUBLIC_HEADER DESTINATION include/modules/services/tx_builder/
    )
endif()

