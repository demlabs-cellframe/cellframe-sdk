cmake_minimum_required(VERSION 3.10)
project(dap_chain_cs)

file(GLOB DAP_CHAIN_CS_SRCS dap_chain_cs.c)
file(GLOB DAP_CHAIN_CS_HEADERS include/dap_chain_cs.h)

message("[+] Module 'chain-cs' (consensus callbacks & common API)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_CS_SRCS} HEADERS ${DAP_CHAIN_CS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# chain_cs needs chain.h for dap_chain_t type - use include path only, no linking
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../chain/include)
target_link_libraries(${PROJECT_NAME} dap_common)

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION lib/modules/consensus/
            ARCHIVE DESTINATION lib/modules/consensus/
            PUBLIC_HEADER DESTINATION include/modules/consensus/
    )
endif()

