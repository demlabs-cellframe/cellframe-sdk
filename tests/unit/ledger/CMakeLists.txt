cmake_minimum_required(VERSION 3.10)

project(test_ledger_tx_operations)

# Include DAP Mock AutoWrap module
include(${DAP_SDK_SOURCE_DIR}/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_ledger_tx_operations.c
)

# No explicit includes needed - all propagate via linked modules

# On macOS, real symbols come from cellframe_sdk (shared, -flat_namespace -interposable)
# and mock_interpose.c overrides them.  We must NOT link the mocked OBJECT library
# directly (duplicate symbols), but we still need its transitive include dirs.
if(APPLE)
    target_link_libraries(${PROJECT_NAME}
        dap_test          # Test framework
        dap_sdk           # DAP SDK
        cellframe_sdk     # Cellframe SDK (shared lib provides all implementations)
    )
    foreach(_mod dap_chain_ledger dap_chain_datum dap_chain_tx_compose)
        if(TARGET ${_mod})
            get_target_property(_inc ${_mod} INCLUDE_DIRECTORIES)
            if(_inc)
                target_include_directories(${PROJECT_NAME} PRIVATE ${_inc})
            endif()
            get_target_property(_iinc ${_mod} INTERFACE_INCLUDE_DIRECTORIES)
            if(_iinc)
                target_include_directories(${PROJECT_NAME} PRIVATE ${_iinc})
            endif()
        endif()
    endforeach()
else()
    target_link_libraries(${PROJECT_NAME}
        dap_test          # Test framework
        dap_sdk           # DAP SDK
        cellframe_sdk     # Cellframe SDK (provides ledger/chain headers)
        dap_chain_ledger  # Ledger module (for --wrap to intercept)
    )
endif()

# Set additional includes for custom mock generation
set(ENV{DAP_MOCK_ADDITIONAL_INCLUDES} "#include \"dap_hash.h\"\n#include \"dap_chain_common.h\"\n#include \"dap_chain_datum.h\"\n#include \"dap_chain_datum_tx.h\"\n#include \"dap_chain_ledger.h\"")

# Auto-generate and apply --wrap flags from DAP_MOCK_DECLARE() and DAP_MOCK_CUSTOM() calls
dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
