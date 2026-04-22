# Canonical version lives in dap-sdk/cmake/LibraryHelpers.cmake.
# This thin forwarder avoids maintaining a diverging copy.
include_guard(GLOBAL)

if(DAP_SDK_NATIVE_SOURCE_DIR)
    # cellframe-node build: dap-sdk already processed, variable is set
    include(${DAP_SDK_NATIVE_SOURCE_DIR}/cmake/LibraryHelpers.cmake)
else()
    # Standalone cellframe-sdk build: dap-sdk submodule
    include(${CMAKE_CURRENT_LIST_DIR}/../dap-sdk/cmake/LibraryHelpers.cmake)
endif()
