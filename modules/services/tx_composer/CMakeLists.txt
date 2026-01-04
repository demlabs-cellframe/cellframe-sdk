cmake_minimum_required(VERSION 3.10)

project(dap_chain_tx_composer)

file(GLOB TX_COMPOSER_SRCS *.c)
file(GLOB TX_COMPOSER_HEADERS include/*.h)

# TX Composer - HIGH-LEVEL service layer
# Composes TX Builder + Signer + Converter
cellframe_add_library(${PROJECT_NAME} ${TX_COMPOSER_SRCS} HEADERS ${TX_COMPOSER_HEADERS})

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_datum      # For Signer, Converter
    dap_chain_ledger     # For sign callbacks
    dap_chain_tx_builder # For TX building
)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${TX_COMPOSER_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/services/tx_composer/
        ARCHIVE DESTINATION lib/modules/services/tx_composer/
        PUBLIC_HEADER DESTINATION include/modules/services/tx_composer/
    )
endif()

