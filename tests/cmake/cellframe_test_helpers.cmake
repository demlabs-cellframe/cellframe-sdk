# Cellframe SDK Test Helpers
# Helper functions for unit tests with mock support
#
# Usage:
#   include(${CMAKE_SOURCE_DIR}/tests/cmake/cellframe_test_helpers.cmake)
#   cellframe_test_link_libraries(my_test)

#
# cellframe_test_link_libraries(TARGET_NAME)
#
# Links test target with appropriate libraries for mocking:
# - Linux: STATIC libraries + GNU ld --wrap
# - macOS: SHARED library + DYLD_INSERT_LIBRARIES interpose
#
function(cellframe_test_link_libraries TARGET_NAME)
    if(APPLE)
        # =======================================================================
        # macOS: Link with SHARED library for DYLD interpose to work
        # =======================================================================
        # Interpose only works for calls between modules (exe → dylib).
        # We link with cellframe_sdk shared library, not static modules.
        
        if(TARGET cellframe_sdk)
            target_link_libraries(${TARGET_NAME} PRIVATE cellframe_sdk)
        else()
            message(FATAL_ERROR "cellframe_test_link_libraries: cellframe_sdk target not found")
        endif()
        
        # Link DAP SDK shared library if available
        if(TARGET dap_sdk)
            target_link_libraries(${TARGET_NAME} PRIVATE dap_sdk)
        endif()
        
        # Add include directories from all modules
        # (shared lib doesn't propagate includes like static libs)
        cellframe_test_add_includes(${TARGET_NAME})
        
        # macOS mock approach:
        # 1. -flat_namespace: all symbols in single namespace (allows override)
        # 2. -undefined dynamic_lookup: __real_ resolved at runtime
        # 3. -export_dynamic: export __wrap_ for dlsym lookup
        target_link_options(${TARGET_NAME} PRIVATE 
            "-Wl,-flat_namespace"
            "-Wl,-undefined,dynamic_lookup"
            "-Wl,-export_dynamic"
        )
        
        # Required frameworks
        target_link_libraries(${TARGET_NAME} PRIVATE 
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
        )
    else()
        # =======================================================================
        # Linux: Link with STATIC libraries for GNU ld --wrap to work
        # =======================================================================
        # --wrap renames symbols at link time, works only with static libs.
        
        # Get list of Cellframe SDK modules
        if(NOT DEFINED CELLFRAME_INTERNAL_MODULES)
            message(FATAL_ERROR "cellframe_test_link_libraries: CELLFRAME_INTERNAL_MODULES not defined")
        endif()
        
        # Link all Cellframe SDK modules as STATIC libraries
        foreach(MODULE ${CELLFRAME_INTERNAL_MODULES})
            if(TARGET ${MODULE}_static)
                target_link_libraries(${TARGET_NAME} PRIVATE ${MODULE}_static)
            else()
                message(WARNING "cellframe_test_link_libraries: Static library ${MODULE}_static not found")
            endif()
        endforeach()
        
        # Also link DAP SDK static modules if available
        get_property(DAP_MODULES CACHE DAP_INTERNAL_MODULES PROPERTY VALUE)
        if(DAP_MODULES)
            foreach(MODULE ${DAP_MODULES})
                if(TARGET ${MODULE}_static)
                    target_link_libraries(${TARGET_NAME} PRIVATE ${MODULE}_static)
                endif()
            endforeach()
        endif()
        
        # Linux system libraries
        target_link_libraries(${TARGET_NAME} PRIVATE pthread m rt)
    endif()
    
    # Link test framework (both platforms)
    if(TARGET dap_test)
        target_link_libraries(${TARGET_NAME} PRIVATE dap_test)
    endif()
    
    # Link dl library (both platforms)
    target_link_libraries(${TARGET_NAME} PRIVATE ${CMAKE_DL_LIBS})
endfunction()

#
# cellframe_test_add_includes(TARGET_NAME)
#
# Adds all Cellframe SDK include directories to target.
#
function(cellframe_test_add_includes TARGET_NAME)
    # Get includes from all Cellframe SDK modules
    if(DEFINED CELLFRAME_INTERNAL_MODULES)
        foreach(MODULE ${CELLFRAME_INTERNAL_MODULES})
            if(TARGET ${MODULE})
                get_target_property(MODULE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
                if(MODULE_INCLUDES)
                    target_include_directories(${TARGET_NAME} PRIVATE ${MODULE_INCLUDES})
                endif()
            endif()
        endforeach()
    endif()
    
    # Get includes from DAP SDK modules
    get_property(DAP_MODULES CACHE DAP_INTERNAL_MODULES PROPERTY VALUE)
    if(DAP_MODULES)
        foreach(MODULE ${DAP_MODULES})
            if(TARGET ${MODULE})
                get_target_property(MODULE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
                if(MODULE_INCLUDES)
                    target_include_directories(${TARGET_NAME} PRIVATE ${MODULE_INCLUDES})
                endif()
            endif()
        endforeach()
    endif()
    
    # Also get includes from shared library target
    if(TARGET cellframe_sdk)
        get_target_property(SDK_INCLUDES cellframe_sdk INTERFACE_INCLUDE_DIRECTORIES)
        if(SDK_INCLUDES)
            target_include_directories(${TARGET_NAME} PRIVATE ${SDK_INCLUDES})
        endif()
    endif()
    
    # Explicit include directories for commonly missing headers
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/modules/datum/tx/include
        ${CMAKE_SOURCE_DIR}/modules/ledger/include
        ${CMAKE_SOURCE_DIR}/modules/common/include
        ${CMAKE_SOURCE_DIR}/modules/chain/include
        ${CMAKE_SOURCE_DIR}/modules/wallet/include
        ${CMAKE_SOURCE_DIR}/modules/type/dag/include
        ${CMAKE_SOURCE_DIR}/modules/type/blocks/include
        ${CMAKE_SOURCE_DIR}/modules/type/none/include
        ${CMAKE_SOURCE_DIR}/modules/net/include
        ${CMAKE_SOURCE_DIR}/modules/net/srv/include
        ${CMAKE_SOURCE_DIR}/modules/net/srv/voting/include
        ${CMAKE_SOURCE_DIR}/modules/consensus/include
    )
endfunction()
