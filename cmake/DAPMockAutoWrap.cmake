# DAP Mock AutoWrap CMake Module
# Provides automatic linker wrapping for DAP mock framework
#
# Usage:
#   include(DAPMockAutoWrap.cmake)
#   dap_mock_autowrap(my_test_target)
#   dap_mock_autowrap_with_static(my_test_target dap_client dap_stream)
#
# This module automatically:
# 1. Scans source files for DAP_MOCK_DECLARE macros
# 2. Generates linker --wrap options
# 3. Applies them to the target
#
# For static libraries, use dap_mock_autowrap_with_static to wrap with --whole-archive

#
# Cellframe SDK shim for dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake
#
# The dap-sdk version currently contains unresolved merge conflict markers, which breaks
# CMake parsing when BUILD_CELLFRAME_SDK_TESTS=ON. To keep Cellframe SDK buildable without
# changing the dap-sdk submodule, we keep a patched copy here and point the generator script
# to the dap-sdk mocks directory.
#
set(DAP_MOCK_AUTOWRAP_MODULE_DIR "${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks"
    CACHE INTERNAL "Directory containing dap_mock_autowrap scripts")

if(NOT EXISTS "${DAP_MOCK_AUTOWRAP_MODULE_DIR}")
    message(FATAL_ERROR "DAPMockAutoWrap: dap-sdk mocks directory not found: ${DAP_MOCK_AUTOWRAP_MODULE_DIR}")
endif()

# Detect script executor (bash on Unix, PowerShell on Windows)
# Note: PowerShell version (ps1) is basic and may not support all features
# Full functionality is available in bash version (sh)
if(NOT DEFINED SCRIPT_EXECUTOR)
    if(UNIX)
        find_program(BASH_EXECUTABLE bash)
        if(BASH_EXECUTABLE)
            set(SCRIPT_EXECUTOR ${BASH_EXECUTABLE} CACHE INTERNAL "Script executor for mock autowrap")
            set(SCRIPT_EXT "sh" CACHE INTERNAL "Script extension for mock autowrap")
        else()
            message(FATAL_ERROR "Bash required for dap_mock_autowrap() on Unix. Please install bash.")
        endif()
    elseif(WIN32)
        find_program(POWERSHELL_EXECUTABLE powershell)
        if(POWERSHELL_EXECUTABLE)
            set(SCRIPT_EXECUTOR ${POWERSHELL_EXECUTABLE} CACHE INTERNAL "Script executor for mock autowrap")
            set(SCRIPT_EXT "ps1" CACHE INTERNAL "Script extension for mock autowrap")
            message(WARNING "Using PowerShell version of dap_mock_autowrap - basic functionality only. Full features require bash.")
        else()
            message(FATAL_ERROR "PowerShell required for dap_mock_autowrap() on Windows. Please install PowerShell.")
        endif()
    endif()
endif()

#
# dap_mock_autowrap(target_name)
#
# Automatically detect DAP_MOCK_DECLARE in target sources and generate --wrap options
#
function(dap_mock_autowrap TARGET_NAME)
    # Get all source files from the target
    get_target_property(TARGET_SOURCES ${TARGET_NAME} SOURCES)
    if(NOT TARGET_SOURCES)
        #message(WARNING "No sources found for target ${TARGET_NAME}")
        return()
    endif()
    
    # Collect all .c and .h files from sources only (not from include directories)
    # This ensures we only scan files explicitly added to the target, not all headers
    set(ALL_SOURCES "")
    foreach(SOURCE_FILE ${TARGET_SOURCES})
        get_filename_component(SOURCE_ABS ${SOURCE_FILE} ABSOLUTE)
        get_filename_component(SOURCE_EXT ${SOURCE_ABS} EXT)
        if(SOURCE_EXT MATCHES "\\.(c|h)$")
            list(APPEND ALL_SOURCES ${SOURCE_ABS})
        endif()
    endforeach()
    
    if(NOT ALL_SOURCES)
        #message(WARNING "No C/H sources found for target ${TARGET_NAME}")
        return()
    endif()
    
    # Use target name as basename for output files
    set(SOURCE_BASENAME ${TARGET_NAME})
    
    # Output files go to build directory (CMAKE_CURRENT_BINARY_DIR)
    # This keeps generated files separate from source files
    # Use target-specific directory to avoid conflicts between multiple test targets
    set(MOCK_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/mock_gen/${TARGET_NAME}")
    file(MAKE_DIRECTORY ${MOCK_GEN_DIR})
    
    set(WRAP_RESPONSE_FILE "${MOCK_GEN_DIR}/${SOURCE_BASENAME}_wrap.txt")
    set(CMAKE_FRAGMENT "${MOCK_GEN_DIR}/${SOURCE_BASENAME}_mocks.cmake")
    set(WRAPPER_TEMPLATE "${MOCK_GEN_DIR}/${SOURCE_BASENAME}_wrappers_template.c")
    set(MACROS_HEADER "${MOCK_GEN_DIR}/${SOURCE_BASENAME}_mock_macros.h")
    set(CUSTOM_MOCKS_HEADER "${MOCK_GEN_DIR}/${SOURCE_BASENAME}_custom_mocks.h")
    set(LINKER_WRAPPER_HEADER "${MOCK_GEN_DIR}/dap_mock_linker_wrapper.h")
    
    # Path to generator script (use saved module directory)
    set(GENERATOR_SCRIPT "${DAP_MOCK_AUTOWRAP_MODULE_DIR}/dap_mock_autowrap.${SCRIPT_EXT}")
    
    if(NOT EXISTS ${GENERATOR_SCRIPT})
        message(FATAL_ERROR "Mock generator script not found: ${GENERATOR_SCRIPT}")
    endif()

    # dap_mock_autowrap.sh expects dap_tpl next to dap-sdk/module/test/mocks/ (i.e. dap-sdk/module/test/dap_tpl/).
    # In some environments the nested submodule uses an SSH URL and can't be cloned. Fall back to centralized dap_tpl.
    set(MOCK_TEST_DAP_TPL_DIR "${DAP_MOCK_AUTOWRAP_MODULE_DIR}/../dap_tpl")
    if(NOT EXISTS "${MOCK_TEST_DAP_TPL_DIR}/dap_tpl.sh" AND EXISTS "${CMAKE_SOURCE_DIR}/tools/dap_tpl/dap_tpl.sh")
        file(MAKE_DIRECTORY "${MOCK_TEST_DAP_TPL_DIR}")
        file(COPY "${CMAKE_SOURCE_DIR}/tools/dap_tpl/" DESTINATION "${MOCK_TEST_DAP_TPL_DIR}"
            PATTERN ".git" EXCLUDE)
    endif()
    
    # STAGE 1: Generate wrap file at configure time
    #message(STATUS "Generating mock wrappers for ${TARGET_NAME}...")

    # Prepare command for mock generation (execute_process)
    set(MOCK_GEN_CMD_STAGE1 ${SCRIPT_EXECUTOR} ${GENERATOR_SCRIPT} ${MOCK_GEN_DIR} ${SOURCE_BASENAME} ${ALL_SOURCES})
    if(DEFINED DAP_TPL_DIR AND EXISTS "${DAP_TPL_DIR}/dap_tpl.sh")
        # Pass CMAKE_SYSTEM_NAME so the script can detect target platform (not just host).
        set(MOCK_GEN_CMD_STAGE1 ${CMAKE_COMMAND} -E env
            "DAP_TPL_DIR=${DAP_TPL_DIR}"
            "CMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
            ${SCRIPT_EXECUTOR} ${GENERATOR_SCRIPT} ${MOCK_GEN_DIR} ${SOURCE_BASENAME} ${ALL_SOURCES})
    endif()

    # Prepare command for mock generation (add_custom_command)
    set(MOCK_GEN_CMD_STAGE2 ${SCRIPT_EXECUTOR} ${GENERATOR_SCRIPT} ${MOCK_GEN_DIR} ${SOURCE_BASENAME} ${ALL_SOURCES})
    if(DEFINED DAP_TPL_DIR AND EXISTS "${DAP_TPL_DIR}/dap_tpl.sh")
        set(MOCK_GEN_CMD_STAGE2 ${CMAKE_COMMAND} -E env
            "DAP_TPL_DIR=${DAP_TPL_DIR}"
            "CMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
            ${SCRIPT_EXECUTOR} ${GENERATOR_SCRIPT} ${MOCK_GEN_DIR} ${SOURCE_BASENAME} ${ALL_SOURCES})
    endif()

    execute_process(
        COMMAND ${MOCK_GEN_CMD_STAGE1}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE MOCK_GEN_RESULT
        OUTPUT_VARIABLE MOCK_GEN_OUTPUT
        ERROR_VARIABLE MOCK_GEN_ERROR
    )
    
    if(NOT MOCK_GEN_RESULT EQUAL 0)
        message(FATAL_ERROR "Mock generator failed for ${TARGET_NAME}:\nEXIT CODE: ${MOCK_GEN_RESULT}\nSTDOUT:\n${MOCK_GEN_OUTPUT}\nSTDERR:\n${MOCK_GEN_ERROR}\n\nMock generator failure is fatal - build aborted.")
    endif()

    # dap_mock_autowrap.sh writes a full _DAP_MOCK_MAP system into "${MACROS_HEADER}.map_content",
    # but the main macros header doesn't include it yet. Fix it up post-generation.
    execute_process(
        COMMAND python3 "${CMAKE_SOURCE_DIR}/cmake/dap_mock_macros_fixup.py"
            --macros "${MACROS_HEADER}"
            --map-content "${MACROS_HEADER}.map_content"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE MOCK_FIXUP_RESULT
        OUTPUT_QUIET
        ERROR_VARIABLE MOCK_FIXUP_ERROR
    )
    if(NOT MOCK_FIXUP_RESULT EQUAL 0)
        message(FATAL_ERROR "Mock macros fix-up failed for ${TARGET_NAME}:\n${MOCK_FIXUP_ERROR}")
    endif()
    
    # On macOS, fix up the interpose file to add __real_* functions
    if(APPLE)
        set(INTERPOSE_FILE "${MOCK_GEN_DIR}/mock_interpose_macos.c")
        if(EXISTS "${INTERPOSE_FILE}")
            execute_process(
                COMMAND python3 "${CMAKE_SOURCE_DIR}/cmake/dap_mock_macos_fixup.py"
                    --interpose "${INTERPOSE_FILE}"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE MACOS_FIXUP_RESULT
                OUTPUT_QUIET
                ERROR_VARIABLE MACOS_FIXUP_ERROR
            )
            if(NOT MACOS_FIXUP_RESULT EQUAL 0)
                message(WARNING "macOS interpose fix-up failed for ${TARGET_NAME}:\n${MACOS_FIXUP_ERROR}")
            endif()
        endif()
    endif()
    
    # STAGE 2: Setup re-generation on source file changes
    add_custom_command(
        OUTPUT ${WRAP_RESPONSE_FILE} ${CMAKE_FRAGMENT} ${MACROS_HEADER} ${CUSTOM_MOCKS_HEADER} ${LINKER_WRAPPER_HEADER}
        COMMAND ${MOCK_GEN_CMD_STAGE2}
        COMMAND python3 "${CMAKE_SOURCE_DIR}/cmake/dap_mock_macros_fixup.py"
            --macros "${MACROS_HEADER}"
            --map-content "${MACROS_HEADER}.map_content"
        DEPENDS ${ALL_SOURCES}
        COMMENT "Regenerating mock wrappers for ${TARGET_NAME}"
        VERBATIM
    )
    
    add_custom_target(${TARGET_NAME}_mock_gen
        DEPENDS ${WRAP_RESPONSE_FILE} ${CMAKE_FRAGMENT} ${CUSTOM_MOCKS_HEADER} ${LINKER_WRAPPER_HEADER}
    )
    add_dependencies(${TARGET_NAME} ${TARGET_NAME}_mock_gen)

    # STAGE 2.5: Add include directory for generated headers
    target_include_directories(${TARGET_NAME} PRIVATE ${MOCK_GEN_DIR})
    # Include generated headers via compiler flag -include
    # This ensures the macros and custom mocks are available before dap_mock.h is processed
    # Files are generated by dap_mock_autowrap.sh (or .ps1 on Windows), so they should exist after generation
    # Use relative filename (not absolute path) since directory is already in include paths
    # This ensures portability across different build machines (CI, local, macOS, Linux)
    # CUSTOM_MOCKS_HEADER includes MACROS_HEADER
    # LINKER_WRAPPER_HEADER is included via #include in dap_mock.h
    get_filename_component(CUSTOM_MOCKS_HEADER_NAME "${CUSTOM_MOCKS_HEADER}" NAME)
    target_compile_options(${TARGET_NAME} PRIVATE "-include" "${CUSTOM_MOCKS_HEADER_NAME}")
    # Also define macro flag to indicate macros are available (for conditional inclusion)
    # This is a flag, not a macro with value - used for #ifdef checks
    target_compile_definitions(${TARGET_NAME} PRIVATE 
        DAP_MOCK_GENERATED_MACROS_H)

    # STAGE 3: Apply wrap options (file should exist now)
    if(EXISTS ${WRAP_RESPONSE_FILE})
        # Check if file is empty (no mocks)
        file(READ ${WRAP_RESPONSE_FILE} WRAP_CONTENT)
        string(STRIP "${WRAP_CONTENT}" WRAP_CONTENT_STRIPPED)
        
        # Only apply wrap options if file is not empty
        if(WRAP_CONTENT_STRIPPED)
            # Detect if compiler supports response files
            if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR
               CMAKE_C_COMPILER_ID MATCHES "Clang" OR
               CMAKE_C_COMPILER_ID MATCHES "AppleClang")
                # GCC and Clang support -Wl,@file for response files
                # Note: macOS generates -Wl,-alias options, Linux generates --wrap options
                target_link_options(${TARGET_NAME} PRIVATE "-Wl,@${WRAP_RESPONSE_FILE}")
                # On macOS, add -flat_namespace and -interposable to make dyld interpose work
                if(APPLE)
                    target_link_options(${TARGET_NAME} PRIVATE "-Wl,-flat_namespace" "-Wl,-interposable")
                endif()
                #message(STATUS "✅ Mock autowrap enabled for ${TARGET_NAME} (via @file)")
            else()
                # Fallback: read file and add options individually
                string(REPLACE "\n" ";" WRAP_OPTIONS_LIST "${WRAP_CONTENT}")
                target_link_options(${TARGET_NAME} PRIVATE ${WRAP_OPTIONS_LIST})
                #message(STATUS "✅ Mock autowrap enabled for ${TARGET_NAME}")
            endif()
            
            # Count wrapped functions (works for both --wrap and -alias)
            string(REGEX MATCHALL "(--wrap=|-alias)" WRAP_MATCHES "${WRAP_CONTENT}")
            list(LENGTH WRAP_MATCHES WRAP_COUNT)
            
            if(WRAP_COUNT GREATER 0)
                if(APPLE)
                    message(STATUS " Mocked ${WRAP_COUNT} functions (macOS -alias)")
                else()
                    message(STATUS " Mocked ${WRAP_COUNT} functions (GNU --wrap)")
                endif()
            endif()
        else()
            # File is empty - don't apply to linker
            #message(STATUS "   No mocks found - empty wrap file (not applied to linker)")
        endif()
        #message(STATUS "   Output: ${MOCK_GEN_DIR}")
    else()
        # File was not generated - create empty stub file (truly empty, no comments)
        # Linker response files cannot contain comments - they are interpreted as options
        file(WRITE ${WRAP_RESPONSE_FILE} "")
        #message(STATUS "   No mocks found for ${TARGET_NAME} - created empty wrap file")
        
        # Don't apply empty file to linker - it will cause errors
        # Empty file is created only for consistency and to avoid file-not-found errors
        #message(STATUS "✅ Mock autowrap enabled for ${TARGET_NAME} (empty wrap file - no mocks)")
    endif()
    
    # AUTOMATIC --whole-archive wrapping for static libraries
    # After generating --wrap flags, automatically wrap all *_static libraries
    # with --whole-archive to ensure --wrap works correctly
    # This eliminates the need for manual dap_mock_autowrap_with_static() calls
    
    # Get list of linked libraries
    get_target_property(LINKED_LIBS ${TARGET_NAME} LINK_LIBRARIES)
    if(LINKED_LIBS)
        # Collect all *_static libraries that need wrapping
        set(STATIC_LIBS_TO_WRAP "")
        foreach(LIB ${LINKED_LIBS})
            if(LIB MATCHES "_static$" AND TARGET ${LIB})
                # This is a static library - add it to wrap list
                list(APPEND STATIC_LIBS_TO_WRAP ${LIB})
            endif()
        endforeach()
        
        # If we found static libraries, wrap them automatically
        if(STATIC_LIBS_TO_WRAP)
            # Remove _static suffix to get base names for dap_mock_autowrap_with_static
            set(BASE_LIBS "")
            foreach(LIB ${STATIC_LIBS_TO_WRAP})
                string(REGEX REPLACE "_static$" "" BASE_LIB "${LIB}")
                list(APPEND BASE_LIBS ${BASE_LIB})
            endforeach()
            
            # Call dap_mock_autowrap_with_static automatically
            dap_mock_autowrap_with_static(${TARGET_NAME} ${BASE_LIBS})
            #message(STATUS "✅ Auto-wrapped ${BASE_LIBS} with --whole-archive for ${TARGET_NAME}")
        endif()
    endif()
endfunction()

#
# dap_mock_autowrap_with_static(target_name library1 library2 ...)
#
# Wrap specified static libraries with --whole-archive and --start-group/--end-group
# to make --wrap work correctly with circular dependencies.
# This forces linker to process all symbols from static libraries and resolve
# circular dependencies properly.
#
# Example:
#   target_link_libraries(test_http dap_core dap_http_server dap_test)
#   dap_mock_autowrap_with_static(test_http dap_http_server)
#
# Result:
#   Links as: dap_core -Wl,--start-group -Wl,--whole-archive dap_http_server -Wl,--no-whole-archive -Wl,--end-group dap_test
#
function(dap_mock_autowrap_with_static TARGET_NAME)
    set(LIBS_TO_WRAP ${ARGN})
    
    if(NOT LIBS_TO_WRAP)
        message(WARNING "dap_mock_autowrap_with_static: No libraries specified")
        return()
    endif()
    
    # Get current link libraries
    get_target_property(CURRENT_LIBS ${TARGET_NAME} LINK_LIBRARIES)
    
    # Also check if libraries are added via target_sources (for OBJECT libraries)
    # This handles the case when dap_test_link_libraries uses target_sources
    # to add object files from dap_sdk_object or individual object libraries
    get_target_property(SOURCES ${TARGET_NAME} SOURCES)
    set(OBJECT_LIBS_TO_WRAP "")
    set(OBJECT_SOURCES_TO_REMOVE "")
    if(SOURCES)
        foreach(SOURCE ${SOURCES})
            # Check if source is a generator expression for object files: $<TARGET_OBJECTS:lib_name>
            if(SOURCE MATCHES "\\$<TARGET_OBJECTS:([^>]+)>")
                set(OBJ_LIB ${CMAKE_MATCH_1})
                # Check if this object library should be wrapped
                # Also check if it's dap_sdk_object which contains all modules
                if(OBJ_LIB STREQUAL "dap_sdk_object")
                    # dap_sdk_object contains all modules - check if any of the requested libs are in it
                    # We need to extract individual object libraries from DAP_INTERNAL_MODULES
                    # and link them separately to enable --wrap
                    get_property(DAP_MODULES CACHE DAP_INTERNAL_MODULES PROPERTY VALUE)
                    if(DAP_MODULES)
                        foreach(MODULE ${DAP_MODULES})
                            list(FIND LIBS_TO_WRAP ${MODULE} MODULE_INDEX)
                            if(MODULE_INDEX GREATER -1)
                                list(APPEND OBJECT_LIBS_TO_WRAP ${MODULE})
                            endif()
                        endforeach()
                        # Always remove dap_sdk_object source if we need to wrap any modules
                        # We'll link individual modules via target_link_libraries instead
                        if(OBJECT_LIBS_TO_WRAP)
                            list(APPEND OBJECT_SOURCES_TO_REMOVE ${SOURCE})
                            # Also need to add remaining modules that are NOT being wrapped
                            # to maintain functionality
                            foreach(MODULE ${DAP_MODULES})
                                list(FIND OBJECT_LIBS_TO_WRAP ${MODULE} MODULE_WRAP_INDEX)
                                if(MODULE_WRAP_INDEX LESS 0)
                                    # This module is not being wrapped - add it to sources to keep it
                                    # Actually, we'll link all modules via target_link_libraries
                                    # to ensure --wrap works for all internal calls
                                endif()
                            endforeach()
                        endif()
                    endif()
                else()
                    # Individual object library
                    list(FIND LIBS_TO_WRAP ${OBJ_LIB} OBJ_LIB_INDEX)
                    if(OBJ_LIB_INDEX GREATER -1)
                        list(APPEND OBJECT_LIBS_TO_WRAP ${OBJ_LIB})
                        # Mark this source for removal - we'll link it via target_link_libraries instead
                        list(APPEND OBJECT_SOURCES_TO_REMOVE ${SOURCE})
                    endif()
                endif()
            endif()
        endforeach()
    endif()
    
    if(NOT CURRENT_LIBS AND NOT OBJECT_LIBS_TO_WRAP)
        message(WARNING "dap_mock_autowrap_with_static: No libraries linked to ${TARGET_NAME}")
        return()
    endif()
    
    # Remove duplicates first
    if(CURRENT_LIBS)
        list(REMOVE_DUPLICATES CURRENT_LIBS)
    else()
        set(CURRENT_LIBS "")
    endif()
    
    # Collect libraries that need wrapping and their dependencies
    set(WRAPPED_LIBS "")
    set(OTHER_LIBS "")
    
    # Process libraries from LINK_LIBRARIES
    # Automatically add _static suffix to library names for proper mocking
    foreach(LIB ${CURRENT_LIBS})
        # Check if this lib should be wrapped (try both with and without _static suffix)
        set(LIB_BASE_NAME ${LIB})
        # Remove _static suffix if present
        string(REGEX REPLACE "_static$" "" LIB_BASE_NAME "${LIB}")
        
        list(FIND LIBS_TO_WRAP ${LIB_BASE_NAME} LIB_INDEX)
        if(LIB_INDEX GREATER -1)
            # This library should be wrapped
            # Use _static version if it exists in CURRENT_LIBS
            if(LIB MATCHES "_static$")
                list(APPEND WRAPPED_LIBS ${LIB})
            elseif(TARGET ${LIB}_static)
                # Static version exists, use it
                list(APPEND WRAPPED_LIBS ${LIB}_static)
            else()
                # No static version, use as is
                list(APPEND WRAPPED_LIBS ${LIB})
            endif()
        else()
            list(APPEND OTHER_LIBS ${LIB})
        endif()
    endforeach()
    
    # Process object libraries from target_sources
    # For object libraries, we need to link them explicitly to enable --wrap
    foreach(OBJ_LIB ${OBJECT_LIBS_TO_WRAP})
        # Remove _static suffix if present
        string(REGEX REPLACE "_static$" "" OBJ_LIB_BASE "${OBJ_LIB}")
        list(FIND LIBS_TO_WRAP ${OBJ_LIB_BASE} WRAP_BASE_INDEX)
        if(WRAP_BASE_INDEX GREATER -1)
            # Try to use static version first
            if(TARGET ${OBJ_LIB}_static)
                list(FIND WRAPPED_LIBS ${OBJ_LIB}_static WRAP_INDEX)
                if(WRAP_INDEX LESS 0)
                    list(APPEND WRAPPED_LIBS ${OBJ_LIB}_static)
                endif()
            else()
                list(FIND WRAPPED_LIBS ${OBJ_LIB} WRAP_INDEX)
                if(WRAP_INDEX LESS 0)
                    list(APPEND WRAPPED_LIBS ${OBJ_LIB})
                endif()
            endif()
        endif()
    endforeach()
    
    # Rebuild link libraries list:
    # - Put wrapped libraries in --start-group with --whole-archive
    # - Put ALL libraries (including dependencies) in the group to prevent duplicate linking
    #   This ensures that --wrap works correctly even when libraries are linked multiple times
    set(NEW_LIBS "")
    
    # Add wrapped libraries in --start-group with --whole-archive
    # Also include all other libraries in the group to handle circular dependencies
    if(WRAPPED_LIBS)
        list(APPEND NEW_LIBS "-Wl,--start-group")
        
        # Add wrapped libraries with --whole-archive
        # For object libraries, DO NOT use --whole-archive (they are object files, not archives)
        # Instead, collect them for linking at the end outside of --whole-archive
        set(OBJECT_LIBS_TO_LINK "")
        foreach(LIB ${WRAPPED_LIBS})
            # Check if this is an object library that was found in target_sources
            list(FIND OBJECT_LIBS_TO_WRAP ${LIB} IS_OBJECT_LIB)
            if(IS_OBJECT_LIB GREATER -1)
                # Object libraries: collect them for linking at the end
                # NOTE: Object libraries CANNOT be wrapped with --whole-archive
                # So --wrap won't work for internal calls between object files
                # This is a known limitation of GNU ld --wrap
                list(APPEND OBJECT_LIBS_TO_LINK ${LIB})
            else()
                # For static libraries, use --whole-archive
                list(APPEND NEW_LIBS "-Wl,--whole-archive")
                list(APPEND NEW_LIBS ${LIB})
                list(APPEND NEW_LIBS "-Wl,--no-whole-archive")
            endif()
        endforeach()
        
        # Add ALL other libraries inside the group (including dependencies)
        # This prevents duplicate linking and ensures --wrap works correctly
        foreach(LIB ${CURRENT_LIBS})
            list(FIND WRAPPED_LIBS ${LIB} WRAP_INDEX)
            if(WRAP_INDEX LESS 0)
                list(APPEND NEW_LIBS ${LIB})
            endif()
        endforeach()
        
        list(APPEND NEW_LIBS "-Wl,--end-group")
    else()
        # No libraries to wrap - just add all libraries normally
        foreach(LIB ${CURRENT_LIBS})
            list(APPEND NEW_LIBS ${LIB})
        endforeach()
    endif()
    
    # Check if we're removing dap_sdk_object before removing sources
    set(HAD_DAP_SDK_OBJECT FALSE)
    if(OBJECT_SOURCES_TO_REMOVE)
        foreach(OBJ_SOURCE ${OBJECT_SOURCES_TO_REMOVE})
            if(OBJ_SOURCE MATCHES "\\$<TARGET_OBJECTS:dap_sdk_object>")
                set(HAD_DAP_SDK_OBJECT TRUE)
                break()
            endif()
        endforeach()
    endif()
    
    # Remove object libraries from target_sources if they need to be wrapped
    # Object libraries must be linked via target_link_libraries (not target_sources)
    # for --wrap to work correctly
    if(OBJECT_SOURCES_TO_REMOVE)
        foreach(OBJ_SOURCE ${OBJECT_SOURCES_TO_REMOVE})
            get_target_property(CURRENT_SOURCES ${TARGET_NAME} SOURCES)
            if(CURRENT_SOURCES)
                list(REMOVE_ITEM CURRENT_SOURCES ${OBJ_SOURCE})
                set_target_properties(${TARGET_NAME} PROPERTIES SOURCES "${CURRENT_SOURCES}")
            endif()
        endforeach()
    endif()
    
    # Clear and reset link libraries
    # Note: We always use PRIVATE keyword to match dap_test_link_libraries pattern
    # which uses PRIVATE in dap_link_all_sdk_modules
    set_target_properties(${TARGET_NAME} PROPERTIES LINK_LIBRARIES "")
    target_link_libraries(${TARGET_NAME} PRIVATE ${NEW_LIBS})
    
    # Link object libraries explicitly to enable --wrap for internal calls
    # Object libraries must be linked via target_link_libraries (not target_sources)
    # for --wrap to work correctly
    # IMPORTANT: When dap_sdk_object is removed, we need to link ALL modules from DAP_INTERNAL_MODULES
    # to maintain functionality, but wrap only the requested ones
    if(OBJECT_LIBS_TO_LINK OR HAD_DAP_SDK_OBJECT)
        # If we had dap_sdk_object and removed it, link all modules from DAP_INTERNAL_MODULES
        # Otherwise, just link the requested object libraries
        if(HAD_DAP_SDK_OBJECT)
            get_property(DAP_MODULES CACHE DAP_INTERNAL_MODULES PROPERTY VALUE)
            if(DAP_MODULES)
                foreach(MODULE ${DAP_MODULES})
                    if(TARGET ${MODULE})
                        target_link_libraries(${TARGET_NAME} PRIVATE $<TARGET_OBJECTS:${MODULE}>)
                    endif()
                endforeach()
            endif()
        else()
            # Link only requested object libraries
            foreach(OBJ_LIB ${OBJECT_LIBS_TO_LINK})
                if(TARGET ${OBJ_LIB})
                    target_link_libraries(${TARGET_NAME} PRIVATE $<TARGET_OBJECTS:${OBJ_LIB}>)
                endif()
            endforeach()
        endif()
    endif()
    
    # Add --allow-multiple-definition to handle duplicate symbols from --whole-archive
    target_link_options(${TARGET_NAME} PRIVATE "-Wl,--allow-multiple-definition")
    
    #message(STATUS "✅ Enabled --whole-archive with --start-group/--end-group for ${LIBS_TO_WRAP} in ${TARGET_NAME}")
endfunction()

#
# dap_mock_manual_wrap(target_name function1 function2 ...)
#
# Manually specify functions to wrap (if you don't want auto-detection)
#
# Example:
#   dap_mock_manual_wrap(test_vpn 
#       dap_stream_write
#       dap_net_tun_create
#       dap_config_get_item_str
#   )
#
function(dap_mock_manual_wrap TARGET_NAME)
    set(WRAP_OPTIONS "")
    
    # Detect compiler and linker type
    if(CMAKE_C_COMPILER_ID MATCHES "MSVC" OR CMAKE_C_SIMULATE_ID MATCHES "MSVC")
        # MSVC does not support --wrap, use /ALTERNATENAME instead
        message(WARNING "MSVC does not support --wrap. Please use MinGW/Clang for mock testing.")
        message(WARNING "Alternative: Use /ALTERNATENAME:_function_name=_mock_function_name")
        foreach(FUNC ${ARGN})
            list(APPEND WRAP_OPTIONS "/ALTERNATENAME:_${FUNC}=_mock_${FUNC}")
        endforeach()
    else()
        # GCC, Clang, MinGW - all support GNU ld --wrap
        foreach(FUNC ${ARGN})
            list(APPEND WRAP_OPTIONS "-Wl,--wrap=${FUNC}")
        endforeach()
    endif()
    
    target_link_options(${TARGET_NAME} PRIVATE ${WRAP_OPTIONS})
    
    list(LENGTH ARGN FUNC_COUNT)
    message(STATUS "✅ Manual mock wrap: ${FUNC_COUNT} functions for ${TARGET_NAME}")
endfunction()

#
# dap_mock_wrap_from_file(target_name wrap_file)
#
# Apply wrap options from a text file (one function per line)
#
# Example:
#   dap_mock_wrap_from_file(test_vpn mocks/vpn_wraps.txt)
#
function(dap_mock_wrap_from_file TARGET_NAME WRAP_FILE)
    get_filename_component(WRAP_FILE_ABS ${WRAP_FILE} ABSOLUTE)
    
    if(NOT EXISTS ${WRAP_FILE_ABS})
        #message(FATAL_ERROR "Wrap file not found: ${WRAP_FILE_ABS}")
    endif()
    
    # Detect if compiler supports response files directly
    if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR 
       CMAKE_C_COMPILER_ID MATCHES "Clang" OR
       CMAKE_C_COMPILER_ID MATCHES "AppleClang")
        # GCC/Clang: use -Wl,@file directly (most efficient)
        target_link_options(${TARGET_NAME} PRIVATE "-Wl,@${WRAP_FILE_ABS}")
        #message(STATUS "✅ Mock wrap from file: ${WRAP_FILE} (via @file)")
        return()
    endif()
    
    # Fallback: parse file manually for other compilers
    file(READ ${WRAP_FILE_ABS} WRAP_CONTENT)
    string(REPLACE "\n" ";" WRAP_LINES "${WRAP_CONTENT}")
    
    set(WRAP_OPTIONS "")
    set(FUNC_LIST "")
    
    foreach(LINE ${WRAP_LINES})
        string(STRIP "${LINE}" LINE_TRIMMED)
        if(LINE_TRIMMED AND NOT LINE_TRIMMED MATCHES "^#")
            string(REGEX REPLACE "^-Wl,--wrap=" "" FUNC_NAME "${LINE_TRIMMED}")
            list(APPEND FUNC_LIST ${FUNC_NAME})
        endif()
    endforeach()
    
    # Build options based on compiler
    if(CMAKE_C_COMPILER_ID MATCHES "MSVC" OR CMAKE_C_SIMULATE_ID MATCHES "MSVC")
        message(WARNING "MSVC does not support --wrap. Please use MinGW/Clang for mock testing.")
        foreach(FUNC ${FUNC_LIST})
            list(APPEND WRAP_OPTIONS "/ALTERNATENAME:_${FUNC}=_mock_${FUNC}")
        endforeach()
    else()
        foreach(FUNC ${FUNC_LIST})
            list(APPEND WRAP_OPTIONS "-Wl,--wrap=${FUNC}")
        endforeach()
    endif()
    
    target_link_options(${TARGET_NAME} PRIVATE ${WRAP_OPTIONS})
    
    list(LENGTH WRAP_OPTIONS FUNC_COUNT)
    message(STATUS "✅ Mock wrap from file: ${FUNC_COUNT} functions from ${WRAP_FILE}")
endfunction()

# Print helpful info
#message(STATUS "DAP Mock AutoWrap CMake module loaded")
