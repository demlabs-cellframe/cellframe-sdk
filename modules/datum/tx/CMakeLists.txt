cmake_minimum_required(VERSION 3.10)
project(dap_chain_tx_compose)

# TX Compose API - Plugin system for TX creation
file(GLOB DAP_CHAIN_TX_COMPOSE_SRCS *.c)
file(GLOB DAP_CHAIN_TX_COMPOSE_HEADERS include/*.h)

message("[+] Module 'datum/tx' - TX Compose Plugin API")

# Create OBJECT library
add_library(${PROJECT_NAME} OBJECT ${DAP_CHAIN_TX_COMPOSE_SRCS})

target_include_directories(${PROJECT_NAME} PUBLIC
    include/
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/  # datum headers
)

# Dependencies: только базовые datum типы и dap_ht
target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_datum
)

# Export headers for other modules
target_include_directories(${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/modules/datum/tx>
)

if (INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        PUBLIC_HEADER "${DAP_CHAIN_TX_COMPOSE_HEADERS}"
    )

    install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/datum/tx/
        ARCHIVE DESTINATION lib/modules/datum/tx/
        PUBLIC_HEADER DESTINATION include/modules/datum/tx/
    )
endif()

