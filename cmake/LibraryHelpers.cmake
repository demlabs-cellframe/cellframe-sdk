# Universal Library Creation Helpers
# Reusable functions for DAP SDK, Cellframe SDK
# Date: 2025-10-07

# Include post-processing for OBJECT libraries
include(${CMAKE_CURRENT_LIST_DIR}/ObjectLibraryIncludePostProcess.cmake)

# =========================================
# CYCLE DETECTION HELPERS
# =========================================
# Global cache-based cycle detection for dependency graph traversal
# Uses CMake CACHE variables to persist visited state across recursive calls

# Create a unique visited set identifier for a traversal
# Usage: _dap_create_visited_set(TARGET_NAME VISITED_SET_VAR)
function(_dap_create_visited_set TARGET_NAME VISITED_SET_VAR)
    # Generate unique identifier based on target name and timestamp
    # This ensures each call to dap_link_libraries gets its own visited set
    string(TIMESTAMP TIMESTAMP_VALUE "%Y%m%d%H%M%S")
    string(RANDOM RANDOM_VALUE LENGTH 8)
    set(${VISITED_SET_VAR} "${TARGET_NAME}_${TIMESTAMP_VALUE}_${RANDOM_VALUE}" PARENT_SCOPE)
endfunction()

# Mark a target as visited in the global cache
# Usage: _dap_mark_visited(TARGET_NAME VISITED_SET_VAR)
function(_dap_mark_visited TARGET_NAME VISITED_SET_VAR)
    set(CACHE_KEY "_DAP_VISITED_${VISITED_SET_VAR}_${TARGET_NAME}")
    set(${CACHE_KEY} "VISITED" CACHE INTERNAL "Cycle detection marker")
endfunction()

# Check if a target has been visited
# Usage: _dap_is_visited(TARGET_NAME VISITED_SET_VAR RESULT_VAR)
function(_dap_is_visited TARGET_NAME VISITED_SET_VAR RESULT_VAR)
    set(CACHE_KEY "_DAP_VISITED_${VISITED_SET_VAR}_${TARGET_NAME}")
    # Read CACHE variable using get_property (more reliable than dereferencing)
    get_property(IS_VISITED_VALUE CACHE ${CACHE_KEY} PROPERTY VALUE)
    if(IS_VISITED_VALUE STREQUAL "VISITED")
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)
    endif()
endfunction()

# Clear visited set for a new traversal
# Usage: _dap_clear_visited_set(VISITED_SET_VAR)
function(_dap_clear_visited_set VISITED_SET_VAR)
    # Track visited targets in a list stored in a cache variable
    set(CACHE_LIST_KEY "_DAP_VISITED_LIST_${VISITED_SET_VAR}")
    # Read CACHE variable using get_property (more reliable)
    get_property(VISITED_LIST CACHE ${CACHE_LIST_KEY} PROPERTY VALUE)
    if(VISITED_LIST)
        foreach(TARGET ${VISITED_LIST})
            set(CACHE_KEY "_DAP_VISITED_${VISITED_SET_VAR}_${TARGET}")
            unset(${CACHE_KEY} CACHE)
        endforeach()
        unset(${CACHE_LIST_KEY} CACHE)
    endif()
endfunction()

# Internal helper: add target to visited list for cleanup
function(_dap_add_to_visited_list TARGET_NAME VISITED_SET_VAR)
    set(CACHE_LIST_KEY "_DAP_VISITED_LIST_${VISITED_SET_VAR}")
    # Read CACHE variable using get_property (more reliable)
    get_property(VISITED_LIST CACHE ${CACHE_LIST_KEY} PROPERTY VALUE)
    if(NOT VISITED_LIST)
        set(VISITED_LIST "")
    endif()
    list(FIND VISITED_LIST ${TARGET_NAME} FOUND)
    if(FOUND EQUAL -1)
        list(APPEND VISITED_LIST ${TARGET_NAME})
        set(${CACHE_LIST_KEY} ${VISITED_LIST} CACHE INTERNAL "Visited targets list")
    endif()
endfunction()

# Helper function to propagate include directories from INTERFACE dependencies
# This is needed because CMake doesn't automatically propagate INTERFACE_INCLUDE_DIRECTORIES
# to OBJECT libraries during compilation
# This function recursively processes all dependencies to ensure transitive includes are propagated
function(propagate_interface_includes_for_object TARGET_NAME)
    get_target_property(TARGET_TYPE ${TARGET_NAME} TYPE)
    if(NOT TARGET_TYPE STREQUAL "OBJECT_LIBRARY")
        return()
    endif()
    
    # Get all linked libraries (INTERFACE dependencies)
    get_target_property(LINK_LIBS ${TARGET_NAME} INTERFACE_LINK_LIBRARIES)
    if(LINK_LIBS)
        foreach(LIB ${LINK_LIBS})
            if(TARGET ${LIB})
                # Get INTERFACE_INCLUDE_DIRECTORIES from dependency (includes PUBLIC)
                get_target_property(LIB_INTERFACE_INCLUDES ${LIB} INTERFACE_INCLUDE_DIRECTORIES)
                if(LIB_INTERFACE_INCLUDES)
                    target_include_directories(${TARGET_NAME} PRIVATE ${LIB_INTERFACE_INCLUDES})
                endif()
                # Also get regular INCLUDE_DIRECTORIES if they exist
                get_target_property(LIB_INCLUDES ${LIB} INCLUDE_DIRECTORIES)
                if(LIB_INCLUDES)
                    target_include_directories(${TARGET_NAME} PRIVATE ${LIB_INCLUDES})
                endif()
                
                # Recursively process dependencies of this library to get transitive includes
                get_target_property(LIB_INTERFACE_DEPS ${LIB} INTERFACE_LINK_LIBRARIES)
                if(LIB_INTERFACE_DEPS)
                    foreach(DEP ${LIB_INTERFACE_DEPS})
                        if(TARGET ${DEP})
                            get_target_property(DEP_INTERFACE_INCLUDES ${DEP} INTERFACE_INCLUDE_DIRECTORIES)
                            if(DEP_INTERFACE_INCLUDES)
                                target_include_directories(${TARGET_NAME} PRIVATE ${DEP_INTERFACE_INCLUDES})
                            endif()
                        endif()
                    endforeach()
                endif()
            endif()
        endforeach()
    endif()
endfunction()

# =========================================
# DAP_LINK_LIBRARIES - Enhanced linking with automatic include propagation
# =========================================
# Links libraries and automatically propagates include directories for OBJECT libraries
# Handles transitive dependencies recursively with cycle detection
# Usage: dap_link_libraries(TARGET_NAME [PUBLIC|PRIVATE|INTERFACE] lib1 lib2 ...)
function(dap_link_libraries TARGET_NAME)
    # For OBJECT libraries, we need to establish build dependencies BEFORE target_link_libraries
    # because target_link_libraries for OBJECT libraries with INTERFACE doesn't create build dependencies
    get_target_property(TGT_TYPE ${TARGET_NAME} TYPE)
    if(TGT_TYPE STREQUAL "OBJECT_LIBRARY")
        # Parse arguments to find libraries (skip scope keywords)
        set(LIBS_TO_PROCESS "")
        set(CURRENT_SCOPE "")
        
        foreach(ARG ${ARGN})
            if(ARG MATCHES "^(PUBLIC|PRIVATE|INTERFACE)$")
                set(CURRENT_SCOPE ${ARG})
            elseif(TARGET ${ARG})
                list(APPEND LIBS_TO_PROCESS ${ARG})
            endif()
        endforeach()
        
        # If no scope specified, INTERFACE is implied for OBJECT libraries
        if(NOT CURRENT_SCOPE AND LIBS_TO_PROCESS)
            set(CURRENT_SCOPE "INTERFACE")
        endif()
        
        # Process dependencies with cycle detection
        if(LIBS_TO_PROCESS AND (CURRENT_SCOPE STREQUAL "INTERFACE" OR CURRENT_SCOPE STREQUAL "PUBLIC"))
            # Create unique visited set for this call to ensure proper cycle detection
            _dap_create_visited_set(${TARGET_NAME} VISITED_SET_INCLUDES)
            
            # IMPORTANT: Establish build dependencies for DIRECT dependencies BEFORE target_link_libraries
            # This ensures that custom build dependencies (like BuildXKCP) are propagated
            # and create proper build order in Makefile
            foreach(DEP ${LIBS_TO_PROCESS})
                if(TARGET ${DEP})
                    # Get build dependencies of this direct dependency
                    get_target_property(DEP_BUILD_DEPS ${DEP} DAP_BUILD_DEPENDENCIES)
                    if(DEP_BUILD_DEPS AND NOT DEP_BUILD_DEPS STREQUAL "DAP_BUILD_DEPENDENCIES-NOTFOUND" AND NOT DEP_BUILD_DEPS STREQUAL "NOTFOUND")
                        # Handle both string and list formats
                        if(DEP_BUILD_DEPS MATCHES ";")
                            set(DEP_BUILD_DEPS_LIST ${DEP_BUILD_DEPS})
                        else()
                            set(DEP_BUILD_DEPS_LIST ${DEP_BUILD_DEPS})
                        endif()
                        foreach(BUILD_DEP ${DEP_BUILD_DEPS_LIST})
                            if(BUILD_DEP AND TARGET ${BUILD_DEP})
                                add_dependencies(${TARGET_NAME} ${BUILD_DEP})
                            endif()
                        endforeach()
                    endif()
                endif()
            endforeach()
            
            # Propagate include directories for DIRECT dependencies only before target_link_libraries
            # Transitive dependencies will be processed after target_link_libraries
            foreach(DEP ${LIBS_TO_PROCESS})
                if(TARGET ${DEP})
                    get_target_property(DEP_INTERFACE_INCLUDES ${DEP} INTERFACE_INCLUDE_DIRECTORIES)
                    get_target_property(DEP_INCLUDES ${DEP} INCLUDE_DIRECTORIES)
                    if(DEP_INTERFACE_INCLUDES)
                        target_include_directories(${TARGET_NAME} PRIVATE ${DEP_INTERFACE_INCLUDES})
                    endif()
                    if(DEP_INCLUDES)
                        target_include_directories(${TARGET_NAME} PRIVATE ${DEP_INCLUDES})
                    endif()
                endif()
            endforeach()
        endif()
    endif()
    
    # Call standard CMake target_link_libraries
    # This establishes link dependencies and propagates INTERFACE properties
    target_link_libraries(${TARGET_NAME} ${ARGN})
    
    # Process transitive dependencies AFTER target_link_libraries
    # This ensures INTERFACE_LINK_LIBRARIES is properly set
    if(TGT_TYPE STREQUAL "OBJECT_LIBRARY" AND LIBS_TO_PROCESS AND (CURRENT_SCOPE STREQUAL "INTERFACE" OR CURRENT_SCOPE STREQUAL "PUBLIC"))
        # Create unique visited sets for transitive processing
        _dap_create_visited_set(${TARGET_NAME} VISITED_SET_INCLUDES_TRANS)
        _dap_create_visited_set(${TARGET_NAME} VISITED_SET_BUILD)
        
        # Mark direct dependencies as visited to avoid reprocessing them
        foreach(DEP ${LIBS_TO_PROCESS})
            if(TARGET ${DEP})
                _dap_mark_visited(${DEP} ${VISITED_SET_INCLUDES_TRANS})
                _dap_add_to_visited_list(${DEP} ${VISITED_SET_INCLUDES_TRANS})
                _dap_mark_visited(${DEP} ${VISITED_SET_BUILD})
                _dap_add_to_visited_list(${DEP} ${VISITED_SET_BUILD})
            endif()
        endforeach()
        
        # Get transitive dependencies from INTERFACE_LINK_LIBRARIES
        get_target_property(TRANSITIVE_DEPS ${TARGET_NAME} INTERFACE_LINK_LIBRARIES)
        if(TRANSITIVE_DEPS)
            # Process transitive includes
            propagate_includes_for_target(${TARGET_NAME} "${TRANSITIVE_DEPS}" ${VISITED_SET_INCLUDES_TRANS})
            
            # Process transitive build dependencies
            propagate_build_dependencies(${TARGET_NAME} "${TRANSITIVE_DEPS}" ${VISITED_SET_BUILD})
        endif()
    endif()
endfunction()

# =========================================
# INCLUDE PROPAGATION WITH CYCLE DETECTION
# =========================================
# Two-phase approach: collect dependencies first, then apply changes
# This ensures consistent state for parallel builds and handles cycles correctly

# Collect transitive include directories from dependencies
# Returns collected includes in RESULT_VAR as a list
# Usage: _collect_transitive_includes(TARGET_NAME DEPENDENCIES VISITED_SET_VAR RESULT_VAR)
function(_collect_transitive_includes TARGET_NAME DEPENDENCIES VISITED_SET_VAR RESULT_VAR)
    set(COLLECTED_INCLUDES ${${RESULT_VAR}})
    
    foreach(DEP ${DEPENDENCIES})
        if(TARGET ${DEP})
            # Check for cycles using global cache
            _dap_is_visited(${DEP} ${VISITED_SET_VAR} IS_VISITED)
            if(IS_VISITED)
                # Cycle detected - stop processing this branch immediately
                # Already collected includes up to this point will be used
                # Further includes should be specified directly by the modules
                continue()
            endif()
            
            # Mark as visited BEFORE recursive calls
            _dap_mark_visited(${DEP} ${VISITED_SET_VAR})
            _dap_add_to_visited_list(${DEP} ${VISITED_SET_VAR})
            
            # Collect direct includes from this dependency
            get_target_property(DEP_INTERFACE_INCLUDES ${DEP} INTERFACE_INCLUDE_DIRECTORIES)
            get_target_property(DEP_INCLUDES ${DEP} INCLUDE_DIRECTORIES)
            
            if(DEP_INTERFACE_INCLUDES)
                list(APPEND COLLECTED_INCLUDES ${DEP_INTERFACE_INCLUDES})
            endif()
            if(DEP_INCLUDES)
                list(APPEND COLLECTED_INCLUDES ${DEP_INCLUDES})
            endif()
            
            # Recursively collect transitive dependencies
            get_target_property(DEP_INTERFACE_DEPS ${DEP} INTERFACE_LINK_LIBRARIES)
            get_target_property(DEP_LINK_DEPS ${DEP} LINK_LIBRARIES)
            
            # Process INTERFACE dependencies (propagated to consumers)
            if(DEP_INTERFACE_DEPS)
                # Update parent scope with current state before recursive call
                set(${RESULT_VAR} ${COLLECTED_INCLUDES} PARENT_SCOPE)
                _collect_transitive_includes(${TARGET_NAME} "${DEP_INTERFACE_DEPS}" ${VISITED_SET_VAR} ${RESULT_VAR})
                # Read updated value from parent scope after recursive call
                set(COLLECTED_INCLUDES ${${RESULT_VAR}})
            endif()
            
            # Process PRIVATE dependencies for OBJECT libraries
            if(DEP_LINK_DEPS)
                get_target_property(DEP_TYPE ${DEP} TYPE)
                if(DEP_TYPE STREQUAL "OBJECT_LIBRARY")
                    # Update parent scope with current state before recursive call
                    set(${RESULT_VAR} ${COLLECTED_INCLUDES} PARENT_SCOPE)
                    _collect_transitive_includes(${TARGET_NAME} "${DEP_LINK_DEPS}" ${VISITED_SET_VAR} ${RESULT_VAR})
                    # Read updated value from parent scope after recursive call
                    set(COLLECTED_INCLUDES ${${RESULT_VAR}})
                endif()
            endif()
        endif()
    endforeach()
    
    # Return collected includes
    set(${RESULT_VAR} ${COLLECTED_INCLUDES} PARENT_SCOPE)
endfunction()

# Apply collected include directories to target
# Usage: _apply_collected_includes(TARGET_NAME COLLECTED_INCLUDES)
function(_apply_collected_includes TARGET_NAME COLLECTED_INCLUDES)
    if(COLLECTED_INCLUDES)
        # Remove duplicates
        list(REMOVE_DUPLICATES COLLECTED_INCLUDES)
        # Apply all includes at once
        target_include_directories(${TARGET_NAME} PRIVATE ${COLLECTED_INCLUDES})
    endif()
endfunction()

# Helper function to propagate includes recursively with cycle detection
# Uses two-phase approach: collect first, then apply
# VISITED_SET_VAR is a unique identifier for this traversal
function(propagate_includes_for_target TARGET_NAME DEPENDENCIES VISITED_SET_VAR)
    # Create unique visited set if not provided
    if(NOT VISITED_SET_VAR OR VISITED_SET_VAR STREQUAL "")
        _dap_create_visited_set(${TARGET_NAME} VISITED_SET_VAR)
    endif()
    
    # Phase 1: Collect all transitive includes
    set(COLLECTED_INCLUDES "")
    _collect_transitive_includes(${TARGET_NAME} "${DEPENDENCIES}" ${VISITED_SET_VAR} COLLECTED_INCLUDES)
    
    # Phase 2: Apply collected includes
    _apply_collected_includes(${TARGET_NAME} "${COLLECTED_INCLUDES}")
    
    # Cleanup visited set
    _dap_clear_visited_set(${VISITED_SET_VAR})
endfunction()

# =========================================
# BUILD DEPENDENCY PROPAGATION WITH CYCLE DETECTION
# =========================================
# Two-phase approach: collect build dependencies first, then apply changes
# Handles custom build dependencies (like BuildXKCP) transitively

# Collect transitive build dependencies from dependencies
# Returns collected build dependencies in RESULT_VAR as a list
# Usage: _collect_transitive_build_deps(TARGET_NAME DEPENDENCIES VISITED_SET_VAR RESULT_VAR)
function(_collect_transitive_build_deps TARGET_NAME DEPENDENCIES VISITED_SET_VAR RESULT_VAR)
    set(COLLECTED_BUILD_DEPS ${${RESULT_VAR}})
    
    foreach(DEP ${DEPENDENCIES})
        if(TARGET ${DEP})
            # Check for cycles using global cache
            _dap_is_visited(${DEP} ${VISITED_SET_VAR} IS_VISITED)
            if(IS_VISITED)
                # Cycle detected - skip transitive processing but still collect direct build deps
                # This is the workaround for cyclic dependencies
                get_target_property(DEP_BUILD_DEPS ${DEP} DAP_BUILD_DEPENDENCIES)
                if(DEP_BUILD_DEPS AND NOT DEP_BUILD_DEPS STREQUAL "DAP_BUILD_DEPENDENCIES-NOTFOUND" AND NOT DEP_BUILD_DEPS STREQUAL "NOTFOUND")
                    if(DEP_BUILD_DEPS MATCHES ";")
                        list(APPEND COLLECTED_BUILD_DEPS ${DEP_BUILD_DEPS})
                    else()
                        list(APPEND COLLECTED_BUILD_DEPS ${DEP_BUILD_DEPS})
                    endif()
                endif()
                continue()
            endif()
            
            # Mark as visited BEFORE recursive calls
            _dap_mark_visited(${DEP} ${VISITED_SET_VAR})
            _dap_add_to_visited_list(${DEP} ${VISITED_SET_VAR})
            
            # Collect direct build dependencies from this dependency
            get_target_property(DEP_BUILD_DEPS ${DEP} DAP_BUILD_DEPENDENCIES)
            if(DEP_BUILD_DEPS AND NOT DEP_BUILD_DEPS STREQUAL "DAP_BUILD_DEPENDENCIES-NOTFOUND" AND NOT DEP_BUILD_DEPS STREQUAL "NOTFOUND")
                if(DEP_BUILD_DEPS MATCHES ";")
                    list(APPEND COLLECTED_BUILD_DEPS ${DEP_BUILD_DEPS})
                else()
                    list(APPEND COLLECTED_BUILD_DEPS ${DEP_BUILD_DEPS})
                endif()
            endif()
            
            # Recursively collect transitive dependencies
            get_target_property(DEP_INTERFACE_DEPS ${DEP} INTERFACE_LINK_LIBRARIES)
            get_target_property(DEP_LINK_DEPS ${DEP} LINK_LIBRARIES)
            
            # Process INTERFACE dependencies (propagated to consumers)
            if(DEP_INTERFACE_DEPS)
                # Update parent scope with current state before recursive call
                set(${RESULT_VAR} ${COLLECTED_BUILD_DEPS} PARENT_SCOPE)
                _collect_transitive_build_deps(${TARGET_NAME} "${DEP_INTERFACE_DEPS}" ${VISITED_SET_VAR} ${RESULT_VAR})
                # Read updated value from parent scope after recursive call
                set(COLLECTED_BUILD_DEPS ${${RESULT_VAR}})
            endif()
            
            # Process PRIVATE dependencies for OBJECT libraries
            if(DEP_LINK_DEPS)
                get_target_property(DEP_TYPE ${DEP} TYPE)
                if(DEP_TYPE STREQUAL "OBJECT_LIBRARY")
                    # Update parent scope with current state before recursive call
                    set(${RESULT_VAR} ${COLLECTED_BUILD_DEPS} PARENT_SCOPE)
                    _collect_transitive_build_deps(${TARGET_NAME} "${DEP_LINK_DEPS}" ${VISITED_SET_VAR} ${RESULT_VAR})
                    # Read updated value from parent scope after recursive call
                    set(COLLECTED_BUILD_DEPS ${${RESULT_VAR}})
                endif()
            endif()
        endif()
    endforeach()
    
    # Return collected build dependencies
    set(${RESULT_VAR} ${COLLECTED_BUILD_DEPS} PARENT_SCOPE)
endfunction()

# Apply collected build dependencies to target
# Usage: _apply_collected_build_deps(TARGET_NAME COLLECTED_BUILD_DEPS)
function(_apply_collected_build_deps TARGET_NAME COLLECTED_BUILD_DEPS)
    if(COLLECTED_BUILD_DEPS)
        # Remove duplicates
        list(REMOVE_DUPLICATES COLLECTED_BUILD_DEPS)
        # Apply all build dependencies at once
        foreach(BUILD_DEP ${COLLECTED_BUILD_DEPS})
            if(BUILD_DEP AND TARGET ${BUILD_DEP})
                add_dependencies(${TARGET_NAME} ${BUILD_DEP})
            endif()
        endforeach()
    endif()
endfunction()

# Helper function to propagate build dependencies recursively with cycle detection
# Uses two-phase approach: collect first, then apply
# VISITED_SET_VAR is a unique identifier for this traversal
function(propagate_build_dependencies TARGET_NAME DEPENDENCIES VISITED_SET_VAR)
    # Create unique visited set if not provided
    if(NOT VISITED_SET_VAR OR VISITED_SET_VAR STREQUAL "")
        _dap_create_visited_set(${TARGET_NAME} VISITED_SET_VAR)
    endif()
    
    # Phase 1: Collect all transitive build dependencies
    set(COLLECTED_BUILD_DEPS "")
    _collect_transitive_build_deps(${TARGET_NAME} "${DEPENDENCIES}" ${VISITED_SET_VAR} COLLECTED_BUILD_DEPS)
    
    # Phase 2: Apply collected build dependencies
    _apply_collected_build_deps(${TARGET_NAME} "${COLLECTED_BUILD_DEPS}")
    
    # Cleanup visited set
    _dap_clear_visited_set(${VISITED_SET_VAR})
endfunction()

# =========================================
# PLATFORM-SPECIFIC LIBRARY NAME
# =========================================
# Returns the platform-specific library name
# Usage: get_library_filename(OUTPUT_VAR library_base_name)
# Example: get_library_filename(LIB_NAME "dap-sdk")
#   Linux:   libdap-sdk.so
#   macOS:   libdap-sdk.dylib
#   Windows: dap-sdk.dll
function(get_library_filename OUTPUT_VAR LIB_BASE_NAME)
    if(WIN32)
        set(${OUTPUT_VAR} "${LIB_BASE_NAME}.dll" PARENT_SCOPE)
    elseif(APPLE)
        set(${OUTPUT_VAR} "lib${LIB_BASE_NAME}.dylib" PARENT_SCOPE)
    else() # Linux and other Unix
        set(${OUTPUT_VAR} "lib${LIB_BASE_NAME}.so" PARENT_SCOPE)
    endif()
endfunction()

# =========================================
# GENERIC OBJECT LIBRARY CREATION
# =========================================
# Creates an OBJECT library for combining into final shared library
# Usage: create_object_library(target_name MODULE_LIST_VAR sources... HEADERS headers...)
# 
# Parameters:
#   target_name       - Name of the library target
#   MODULE_LIST_VAR   - Variable name to append this module to (e.g., "DAP_INTERNAL_MODULES")
#   sources...        - Source files
#   HEADERS headers   - Header files (optional)
macro(create_object_library TARGET_NAME MODULE_LIST_VAR)
    cmake_parse_arguments(OBJ_LIB "" "" "HEADERS" ${ARGN})
    
    # Create OBJECT library
    add_library(${TARGET_NAME} OBJECT ${OBJ_LIB_UNPARSED_ARGUMENTS} ${OBJ_LIB_HEADERS})
    
    # Enable position independent code for shared library
    set_property(TARGET ${TARGET_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
    
    # Store original target_link_libraries command for later use
    # We'll override it to auto-propagate include directories
    if(NOT COMMAND _original_target_link_libraries)
        macro(_original_target_link_libraries)
            _target_link_libraries(${ARGN})
        endmacro()
    endif()
    
    # Track module in the provided list variable
    if(NOT DEFINED ${MODULE_LIST_VAR})
        set(${MODULE_LIST_VAR} "" CACHE INTERNAL "List of object modules for ${TARGET_NAME}")
    endif()
    # Check if module is already in list to avoid duplicates
    list(FIND ${MODULE_LIST_VAR} ${TARGET_NAME} MODULE_INDEX)
    if(MODULE_INDEX EQUAL -1)
        list(APPEND ${MODULE_LIST_VAR} ${TARGET_NAME})
        set(${MODULE_LIST_VAR} ${${MODULE_LIST_VAR}} CACHE INTERNAL "List of object modules")
    endif()
    
    # Register OBJECT library for post-processing
    register_object_library(${TARGET_NAME})
    
    # Set directory property for DapModule.cmake to find current target
    set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY DAP_CURRENT_TARGET ${TARGET_NAME})
    
    message(STATUS "[SDK] Module: ${TARGET_NAME} (OBJECT)")
endmacro()


# =========================================
# CREATE COMBINED OBJECT LIBRARY FROM MODULES
# =========================================
# Creates a single OBJECT library from multiple OBJECT library modules
# This is useful for tests where --wrap needs to work for internal calls
# Usage: create_combined_object_library(
#            TARGET_NAME "dap_sdk_object"
#            MODULE_LIST_VAR DAP_INTERNAL_MODULES
#        )
function(create_combined_object_library)
    cmake_parse_arguments(
        COMBINED_OBJ
        ""
        "TARGET_NAME;MODULE_LIST_VAR"
        ""
        ${ARGN}
    )
    
    if(NOT COMBINED_OBJ_TARGET_NAME)
        message(FATAL_ERROR "create_combined_object_library: TARGET_NAME is required")
    endif()
    
    if(NOT COMBINED_OBJ_MODULE_LIST_VAR)
        message(FATAL_ERROR "create_combined_object_library: MODULE_LIST_VAR is required")
    endif()
    
    if(NOT DEFINED ${COMBINED_OBJ_MODULE_LIST_VAR} OR NOT ${COMBINED_OBJ_MODULE_LIST_VAR})
        message(WARNING "create_combined_object_library: No modules registered in ${COMBINED_OBJ_MODULE_LIST_VAR}")
        return()
    endif()
    
    # Collect all object files from OBJECT modules
    set(ALL_OBJECTS "")
    foreach(MODULE ${${COMBINED_OBJ_MODULE_LIST_VAR}})
        if(TARGET ${MODULE})
            list(APPEND ALL_OBJECTS $<TARGET_OBJECTS:${MODULE}>)
        else()
            message(WARNING "create_combined_object_library: Module ${MODULE} is registered but target does not exist")
        endif()
    endforeach()
    
    if(NOT ALL_OBJECTS)
        message(WARNING "create_combined_object_library: No object files collected from modules")
        return()
    endif()
    
    # Create single OBJECT library from all modules
    add_library(${COMBINED_OBJ_TARGET_NAME} OBJECT ${ALL_OBJECTS})
    set_property(TARGET ${COMBINED_OBJ_TARGET_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
    
    # Propagate include directories from all modules
    foreach(MODULE ${${COMBINED_OBJ_MODULE_LIST_VAR}})
        if(TARGET ${MODULE})
            # Get INTERFACE_INCLUDE_DIRECTORIES
            get_target_property(MODULE_INTERFACE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
            if(MODULE_INTERFACE_INCLUDES)
                target_include_directories(${COMBINED_OBJ_TARGET_NAME} PRIVATE ${MODULE_INTERFACE_INCLUDES})
            endif()
            
            # Get INCLUDE_DIRECTORIES (PUBLIC/PRIVATE)
            get_target_property(MODULE_INCLUDES ${MODULE} INCLUDE_DIRECTORIES)
            if(MODULE_INCLUDES)
                target_include_directories(${COMBINED_OBJ_TARGET_NAME} PRIVATE ${MODULE_INCLUDES})
            endif()
        endif()
    endforeach()
    
    message(STATUS "[SDK] Combined OBJECT library created: ${COMBINED_OBJ_TARGET_NAME}")
    message(STATUS "[SDK]   Modules: ${${COMBINED_OBJ_MODULE_LIST_VAR}}")
endfunction()
# Creates final shared library from OBJECT modules
# Usage: create_final_shared_library(
#            LIBRARY_NAME "dap-sdk"
#            MODULE_LIST_VAR DAP_INTERNAL_MODULES
#            VERSION "2.4.0"
#            VERSION_MAJOR 2
#            [LINK_LIBRARIES lib1 lib2 ...]
#        )
function(create_final_shared_library)
    cmake_parse_arguments(
        FINAL_LIB
        ""
        "LIBRARY_NAME;MODULE_LIST_VAR;VERSION;VERSION_MAJOR"
        "LINK_LIBRARIES;ADDITIONAL_SOURCES"
        ${ARGN}
    )
    
    if(NOT DEFINED ${FINAL_LIB_MODULE_LIST_VAR})
        message(FATAL_ERROR "No modules registered in ${FINAL_LIB_MODULE_LIST_VAR}! Call create_object_library() first.")
    endif()
    
    # Get library filename for current platform
    get_library_filename(LIB_FILENAME ${FINAL_LIB_LIBRARY_NAME})
    
    message(STATUS "========================================")
    if(BUILD_SHARED)
        message(STATUS "[SDK] Creating final SHARED library: ${FINAL_LIB_LIBRARY_NAME}")
    else()
        message(STATUS "[SDK] Creating final STATIC library: ${FINAL_LIB_LIBRARY_NAME}")
    endif()
    message(STATUS "[SDK] OBJECT modules: ${${FINAL_LIB_MODULE_LIST_VAR}}")
    if(FINAL_LIB_ADDITIONAL_SOURCES)
        message(STATUS "[SDK] Additional sources: ${FINAL_LIB_ADDITIONAL_SOURCES}")
    endif()
    message(STATUS "========================================")
    
    # Collect all object files
    set(ALL_OBJECTS "")
    foreach(MODULE ${${FINAL_LIB_MODULE_LIST_VAR}})
        if(TARGET ${MODULE})
            list(APPEND ALL_OBJECTS $<TARGET_OBJECTS:${MODULE}>)
        else()
            message(WARNING "[SDK] Module ${MODULE} is registered but target does not exist")
        endif()
    endforeach()
    
    # Create final library (SHARED or STATIC based on BUILD_SHARED option)
    # CMake doesn't allow hyphens in target names, so use underscores for target
    # but set OUTPUT_NAME to the desired name with hyphens
    string(REPLACE "-" "_" TARGET_NAME "${FINAL_LIB_LIBRARY_NAME}")
    
    # Determine library type
    if(BUILD_SHARED)
        set(LIB_TYPE "SHARED")
        message(STATUS "[LibraryHelpers] Creating SHARED library target: ${TARGET_NAME}")
    else()
        set(LIB_TYPE "STATIC")
        message(STATUS "[LibraryHelpers] Creating STATIC library target: ${TARGET_NAME}")
    endif()
    
    message(STATUS "[LibraryHelpers] Target name: ${TARGET_NAME} with OUTPUT_NAME: ${FINAL_LIB_LIBRARY_NAME}")
    add_library(${TARGET_NAME} ${LIB_TYPE} ${ALL_OBJECTS} ${FINAL_LIB_ADDITIONAL_SOURCES})
    
    # If we have additional sources, inherit include directories from all modules
    if(FINAL_LIB_ADDITIONAL_SOURCES)
        foreach(MODULE ${${FINAL_LIB_MODULE_LIST_VAR}})
            if(TARGET ${MODULE})
                # Get INTERFACE_INCLUDE_DIRECTORIES from OBJECT library
                get_target_property(MODULE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
                if(MODULE_INCLUDES)
                    target_include_directories(${TARGET_NAME} PRIVATE ${MODULE_INCLUDES})
                endif()
            endif()
        endforeach()
    endif()
    
    # Set versioning and output name
    # OUTPUT_NAME should be without 'lib' prefix and without extension
    # CMake will automatically add 'lib' prefix for libraries on Unix
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "${FINAL_LIB_LIBRARY_NAME}"
    )
    
    # VERSION and SOVERSION only for SHARED libraries
    if(BUILD_SHARED AND DEFINED FINAL_LIB_VERSION)
        set_target_properties(${TARGET_NAME} PROPERTIES
            VERSION ${FINAL_LIB_VERSION}
            SOVERSION ${FINAL_LIB_VERSION_MAJOR}
        )
    endif()
    
    # Link dependencies
    if(DEFINED FINAL_LIB_LINK_LIBRARIES)
        target_link_libraries(${TARGET_NAME} PRIVATE ${FINAL_LIB_LINK_LIBRARIES})
    endif()
    
    # Link system libraries
    target_link_libraries(${TARGET_NAME} PUBLIC ${CMAKE_DL_LIBS})
    
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        # Linux: link pthread, math, and realtime libraries
        target_link_libraries(${TARGET_NAME} PUBLIC pthread m rt)
    elseif(ANDROID)
        # Android: pthread is built into libc, only link math and log
        target_link_libraries(${TARGET_NAME} PUBLIC m log)
    elseif(APPLE)
        # macOS: link pthread and required frameworks
        target_link_libraries(${TARGET_NAME} PUBLIC pthread)
        # Link macOS system frameworks (required for network monitoring and system APIs)
        target_link_libraries(${TARGET_NAME} PUBLIC 
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
        )
    elseif(WIN32)
        target_link_libraries(${TARGET_NAME} PUBLIC ws2_32 mswsock)
    endif()
    
    # Export all symbols (needed for plugin system)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR (CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT APPLE AND NOT ANDROID))
        # Linux with GNU or Clang
        target_link_options(${TARGET_NAME} PRIVATE -Wl,--export-dynamic)
    elseif(APPLE)
        # macOS with Apple ld
        target_link_options(${TARGET_NAME} PRIVATE -Wl,-export_dynamic)
    elseif(ANDROID)
        # Android NDK - export-dynamic is supported but may need different flags
        target_link_options(${TARGET_NAME} PRIVATE -Wl,--export-dynamic)
    endif()
    
    # =========================================
    # COLLECT INCLUDE DIRECTORIES FROM MODULES
    # =========================================
    # Automatically collect all PUBLIC/INTERFACE include directories from OBJECT modules
    # This allows consumers (like cellframe-node) to see all headers without manual enumeration
    set(ALL_INCLUDE_DIRS "")
    foreach(MODULE ${${FINAL_LIB_MODULE_LIST_VAR}})
        if(TARGET ${MODULE})
            # Get INTERFACE_INCLUDE_DIRECTORIES from OBJECT library
            get_target_property(MODULE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
            if(MODULE_INCLUDES)
                list(APPEND ALL_INCLUDE_DIRS ${MODULE_INCLUDES})
            endif()
        endif()
    endforeach()
    
    # Remove duplicates
    if(ALL_INCLUDE_DIRS)
        list(REMOVE_DUPLICATES ALL_INCLUDE_DIRS)
        list(LENGTH ALL_INCLUDE_DIRS INCLUDE_COUNT)
        message(STATUS "[SDK] Collected ${INCLUDE_COUNT} unique include directories from modules")
    endif()
    
    # Set include directories for consumers
    # Include directories from modules are already absolute paths (CMAKE_CURRENT_SOURCE_DIR)
    # so we can add them directly for BUILD interface
    if(ALL_INCLUDE_DIRS)
        # Add collected include directories directly (they are absolute paths)
        target_include_directories(${TARGET_NAME} INTERFACE ${ALL_INCLUDE_DIRS})
        message(STATUS "[SDK] Exported ${INCLUDE_COUNT} include directories for consumers")
    else()
        message(WARNING "[SDK] No include directories collected from modules")
    endif()
    
    # Add install interface
    target_include_directories(${TARGET_NAME} INTERFACE
        $<INSTALL_INTERFACE:include/${FINAL_LIB_LIBRARY_NAME}>
    )
    
    message(STATUS "[SDK] Final library configured: ${LIB_FILENAME}")
endfunction()

# =========================================
# COLLECT EXTERNAL LIBRARIES FROM OBJECT MODULES
# =========================================
# Collects all external (non-OBJECT) libraries from a list of OBJECT modules
# This is useful for tests and final library linking
# Usage: collect_external_libraries_from_modules(MODULE_LIST RESULT_VAR)
#   MODULE_LIST - list of module names (e.g., ${DAP_INTERNAL_MODULES})
#   RESULT_VAR  - output variable name for collected libraries
function(collect_external_libraries_from_modules MODULE_LIST RESULT_VAR)
    set(ALL_EXTERNAL_LIBS "")
    
    foreach(MODULE ${MODULE_LIST})
        if(TARGET ${MODULE})
            # Collect INTERFACE_LINK_LIBRARIES from each module
            get_target_property(MODULE_INTERFACE_LIBS ${MODULE} INTERFACE_LINK_LIBRARIES)
            if(MODULE_INTERFACE_LIBS)
                foreach(LIB ${MODULE_INTERFACE_LIBS})
                    if(TARGET ${LIB})
                        # Check if it's an OBJECT library (internal) or external library
                        get_target_property(LIB_TYPE ${LIB} TYPE)
                        if(NOT LIB_TYPE STREQUAL "OBJECT_LIBRARY")
                            # External library - collect it
                            list(APPEND ALL_EXTERNAL_LIBS ${LIB})
                        endif()
                    else()
                        # System library (like pthread, rt, dl)
                        list(APPEND ALL_EXTERNAL_LIBS ${LIB})
                    endif()
                endforeach()
            endif()
        endif()
    endforeach()
    
    # Remove duplicates
    if(ALL_EXTERNAL_LIBS)
        list(REMOVE_DUPLICATES ALL_EXTERNAL_LIBS)
    endif()
    
    set(${RESULT_VAR} ${ALL_EXTERNAL_LIBS} PARENT_SCOPE)
endfunction()

# =========================================
# LINK ALL SDK MODULES TO TARGET
# =========================================
# Universal function to link all SDK object modules and their external dependencies
# Works for both applications and tests
# Usage: dap_link_all_sdk_modules(TARGET MODULE_LIST_VAR [LINK_LIBRARIES ...])
#   TARGET           - executable or library target name
#   MODULE_LIST_VAR  - variable containing list of SDK modules (e.g., DAP_INTERNAL_MODULES)
#   LINK_LIBRARIES   - optional additional libraries to link
function(dap_link_all_sdk_modules TARGET MODULE_LIST_VAR)
    # Parse optional LINK_LIBRARIES argument
    cmake_parse_arguments(LINK_ALL "" "" "LINK_LIBRARIES" ${ARGN})
    
    # Get list of SDK modules from cache
    get_property(SDK_MODULES CACHE ${MODULE_LIST_VAR} PROPERTY VALUE)
    
    if(NOT SDK_MODULES)
        message(FATAL_ERROR "dap_link_all_sdk_modules: No modules found in ${MODULE_LIST_VAR}")
    endif()
    
    # Collect object files from all SDK modules
    set(ALL_OBJECTS "")
    foreach(MODULE ${SDK_MODULES})
        if(TARGET ${MODULE})
            list(APPEND ALL_OBJECTS $<TARGET_OBJECTS:${MODULE}>)
        endif()
    endforeach()
    
    # Add all SDK object files to the target
    target_sources(${TARGET} PRIVATE ${ALL_OBJECTS})
    
    # Collect and link all external libraries from SDK modules
    collect_external_libraries_from_modules("${SDK_MODULES}" ALL_EXTERNAL_LIBS)
    if(ALL_EXTERNAL_LIBS)
        target_link_libraries(${TARGET} PRIVATE ${ALL_EXTERNAL_LIBS})
#        message(STATUS "[DAP SDK] ${TARGET}: Linked external libs: ${ALL_EXTERNAL_LIBS}")
    endif()
    
    # Link additional libraries if provided
    if(LINK_ALL_LINK_LIBRARIES)
        target_link_libraries(${TARGET} PRIVATE ${LINK_ALL_LINK_LIBRARIES})
#        message(STATUS "[DAP SDK] ${TARGET}: Additional libs: ${LINK_ALL_LINK_LIBRARIES}")
    endif()
    
#    message(STATUS "[DAP SDK] ${TARGET}: Linked all SDK modules from ${MODULE_LIST_VAR}")
endfunction()

# =========================================
# AUTOMATIC INSTALL PATH SETUP
# =========================================
# Automatically determines install paths based on target name and project structure
# Usage: dap_setup_install_paths(TARGET_NAME [HEADERS headers_list])
# 
# For target "dap_net_transport" in "dap-sdk/net/transport/", automatically sets:
# - LIBRARY DESTINATION: lib/dap/net/transport/
# - ARCHIVE DESTINATION: lib/dap/net/transport/
# - PUBLIC_HEADER DESTINATION: include/dap/net/transport/
function(dap_setup_install_paths TARGET_NAME)
    cmake_parse_arguments(
        SETUP_INSTALL
        ""
        ""
        "HEADERS"
        ${ARGN}
    )
    
    if(NOT INSTALL_DAP_SDK)
        return()
    endif()
    
    # Get current source directory relative to dap-sdk root
    # We need to find the dap-sdk root first
    get_filename_component(CURRENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
    
    # Try to find dap-sdk root by looking for common markers
    set(DAP_SDK_ROOT "")
    set(SEARCH_DIR "${CURRENT_DIR}")
    while(SEARCH_DIR AND NOT SEARCH_DIR STREQUAL "/")
        if(EXISTS "${SEARCH_DIR}/dap-sdk.c" OR EXISTS "${SEARCH_DIR}/CMakeLists.txt")
            # Check if this looks like dap-sdk root
            if(EXISTS "${SEARCH_DIR}/core" AND EXISTS "${SEARCH_DIR}/net")
                set(DAP_SDK_ROOT "${SEARCH_DIR}")
                break()
            endif()
        endif()
        get_filename_component(SEARCH_DIR "${SEARCH_DIR}" DIRECTORY)
    endwhile()
    
    # If we couldn't find dap-sdk root, try common location
    if(NOT DAP_SDK_ROOT)
        # Try relative to current dir
        if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../core")
            get_filename_component(DAP_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
        else()
            # Fallback: use current directory as base
            set(DAP_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
        endif()
    endif()
    
    # Calculate relative path from dap-sdk root
    file(RELATIVE_PATH REL_PATH "${DAP_SDK_ROOT}" "${CMAKE_CURRENT_SOURCE_DIR}")
    
    # Convert path separators and build install path
    string(REPLACE "/" "/" NORMALIZED_PATH "${REL_PATH}")
    string(REPLACE "\\" "/" NORMALIZED_PATH "${NORMALIZED_PATH}")
    
    # Remove leading/trailing slashes
    string(REGEX REPLACE "^/*" "" NORMALIZED_PATH "${NORMALIZED_PATH}")
    string(REGEX REPLACE "/*$" "" NORMALIZED_PATH "${NORMALIZED_PATH}")
    
    # Build install paths
    set(LIB_INSTALL_PATH "lib/dap/${NORMALIZED_PATH}")
    set(INCLUDE_INSTALL_PATH "include/dap/${NORMALIZED_PATH}")
    
    # Clean up paths (remove any double slashes)
    string(REPLACE "//" "/" LIB_INSTALL_PATH "${LIB_INSTALL_PATH}")
    string(REPLACE "//" "/" INCLUDE_INSTALL_PATH "${INCLUDE_INSTALL_PATH}")
    
    # Set PUBLIC_HEADER property if headers provided
    if(SETUP_INSTALL_HEADERS)
        set_target_properties(${TARGET_NAME} PROPERTIES PUBLIC_HEADER "${SETUP_INSTALL_HEADERS}")
    endif()
    
    # Setup install rules
    install(TARGETS ${TARGET_NAME}
            LIBRARY DESTINATION ${LIB_INSTALL_PATH}
            ARCHIVE DESTINATION ${LIB_INSTALL_PATH}
            PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_PATH}
    )
    
    message(STATUS "[DAP SDK] ${TARGET_NAME}: Install paths: lib=${LIB_INSTALL_PATH}, headers=${INCLUDE_INSTALL_PATH}")
endfunction()
# Installs library, headers, and pkg-config profile
# Usage: install_sdk_library(
#            LIBRARY_NAME "dap-sdk"
#            HEADER_DIRECTORIES "core/include" "crypto/include" ...
#            PKGCONFIG_TEMPLATE "dap-sdk.pc.in"
#            [INSTALL_3RDPARTY_HEADERS "3rdparty/uthash/src"]
#        )
function(install_sdk_library)
    cmake_parse_arguments(
        INSTALL_SDK
        ""
        "LIBRARY_NAME;PKGCONFIG_TEMPLATE"
        "HEADER_DIRECTORIES;INSTALL_3RDPARTY_HEADERS"
        ${ARGN}
    )
    
    set(INSTALL_INCLUDEDIR "include/${INSTALL_SDK_LIBRARY_NAME}")
    set(INSTALL_LIBDIR "lib")
    
    # Install the shared library
    install(TARGETS ${INSTALL_SDK_LIBRARY_NAME}
        EXPORT ${INSTALL_SDK_LIBRARY_NAME}_targets
        LIBRARY DESTINATION ${INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${INSTALL_LIBDIR}
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION ${INSTALL_INCLUDEDIR}
    )
    
    # Install headers from specified directories
    if(DEFINED INSTALL_SDK_HEADER_DIRECTORIES)
        foreach(HEADER_DIR ${INSTALL_SDK_HEADER_DIRECTORIES})
            install(DIRECTORY ${HEADER_DIR}/
                DESTINATION ${INSTALL_INCLUDEDIR}
                FILES_MATCHING PATTERN "*.h"
            )
        endforeach()
    endif()
    
    # Install 3rd party headers if specified
    if(DEFINED INSTALL_SDK_INSTALL_3RDPARTY_HEADERS)
        foreach(THIRDPARTY_DIR ${INSTALL_SDK_INSTALL_3RDPARTY_HEADERS})
            get_filename_component(DIR_NAME ${THIRDPARTY_DIR} NAME)
            install(DIRECTORY ${THIRDPARTY_DIR}/
                DESTINATION ${INSTALL_INCLUDEDIR}/${DIR_NAME}
                FILES_MATCHING PATTERN "*.h"
            )
        endforeach()
    endif()
    
    # Install CMake config files
    install(EXPORT ${INSTALL_SDK_LIBRARY_NAME}_targets
        FILE ${INSTALL_SDK_LIBRARY_NAME}_targets.cmake
        NAMESPACE ${INSTALL_SDK_LIBRARY_NAME}::
        DESTINATION ${INSTALL_LIBDIR}/cmake/${INSTALL_SDK_LIBRARY_NAME}
    )
    
    # Generate and install pkg-config file if template provided
    if(DEFINED INSTALL_SDK_PKGCONFIG_TEMPLATE)
        configure_file(
            ${INSTALL_SDK_PKGCONFIG_TEMPLATE}
            ${CMAKE_CURRENT_BINARY_DIR}/${INSTALL_SDK_LIBRARY_NAME}.pc
            @ONLY
        )
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${INSTALL_SDK_LIBRARY_NAME}.pc
            DESTINATION ${INSTALL_LIBDIR}/pkgconfig
        )
    endif()
    
    message(STATUS "[SDK] Installation configured for ${INSTALL_SDK_LIBRARY_NAME}")
endfunction()

