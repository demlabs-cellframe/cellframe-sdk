cmake_minimum_required(VERSION 3.10)
project (dap_chain_crypto)
  
file(GLOB DAP_CHAIN_CRYPTO_SRCS *.c)

file(GLOB DAP_CHAIN_CRYPTO_HEADERS include/*.h)

include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${monero_crypto_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CRYPTO_SRCS} ${DAP_CHAIN_CRYPTO_HEADERS})

target_include_directories(dap_chain_crypto INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain monero_crypto)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

if (${BUILD_DAP_CHAIN_CRYPTO_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CRYPTO_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/mining/
        ARCHIVE DESTINATION lib/modules/mining/
        PUBLIC_HEADER DESTINATION include/modules/mining/
)
endif()