cmake_minimum_required(VERSION 3.10)
project(stream_defrag_integration_tests)

# Stream defragmentation integration tests
# Tests the dap_stream reassembly path for:
# 1. Large packet fragmentation round-trip
# 2. Out-of-order fragment handling
# 3. Bounds checking (OOM cap, overflow prevention)
add_executable(${PROJECT_NAME}
    test_stream_defrag.c
    main.c
    $<TARGET_OBJECTS:test_fixtures>
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_test(
    NAME stream_defrag_integration_tests
    COMMAND ${PROJECT_NAME}
)
