cmake_minimum_required(VERSION 3.10)
project(complex_wallet C)

# Find CellFrame SDK
find_package(CellFrame REQUIRED)

# Create executable
add_executable(${PROJECT_NAME}
    main.c
    wallet.c
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CELLFRAME_INCLUDE_DIRS}
)

# Link CellFrame SDK libraries
target_link_libraries(${PROJECT_NAME}
    cellframe-sdk
    dap_core
    dap_common
    dap_config
    dap_crypto
    dap_chain
    dap_wallet
    dap_mempool
    dap_net
)

# Compile options
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g  # Include debug symbols
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Print build information
message(STATUS "Complex Wallet Example configured:")
message(STATUS "  CellFrame SDK: ${CELLFRAME_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")


