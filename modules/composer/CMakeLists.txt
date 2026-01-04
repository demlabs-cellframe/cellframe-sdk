cmake_minimum_required(VERSION 3.10)

project(dap_chain_composer)

file(GLOB COMPOSER_SRCS *.c)
file(GLOB COMPOSER_HEADERS include/*.h)

# Composer - TX Factory (Builder + Composer + Signer integration)
# 
# Единый модуль для создания транзакций:
# - TX Builder (PURE functions - assembly from UTXO)
# - TX Composer (orchestration - find UTXO, build, sign, convert)
# - Registry API для расширения
cellframe_add_library(${PROJECT_NAME} ${COMPOSER_SRCS} HEADERS ${COMPOSER_HEADERS})

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_datum      # For TX structures, Signer, Converter
    dap_chain_ledger     # For UTXO queries, sign callbacks
)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${COMPOSER_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/composer/
        ARCHIVE DESTINATION lib/modules/composer/
        PUBLIC_HEADER DESTINATION include/modules/composer/
    )
endif()
