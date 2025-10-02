cmake_minimum_required(VERSION 3.10)
project(dap_common)

file(GLOB DAP_COMMON_SRCS *.c)
file(GLOB DAP_COMMON_HEADERS include/*.h *.h)

message("[+] Module 'common' (base types and utilities)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_COMMON_SRCS} HEADERS ${DAP_COMMON_HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC include)

# Only depends on DAP SDK for basic types
# policy.c needs chain.h and datum headers - add include paths only, no linking to avoid cycles
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../chain/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../datum/include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_stream dap_global_db)

if(INSTALL_SDK)
    INSTALL(FILES ${DAP_COMMON_HEADERS}
            DESTINATION include/modules/common/
    )
endif()
