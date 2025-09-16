#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "dap_json-c::dap_json-c" for configuration "Release"
set_property(TARGET dap_json-c::dap_json-c APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(dap_json-c::dap_json-c PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libdap_json-c.a"
  )

list(APPEND _cmake_import_check_targets dap_json-c::dap_json-c )
list(APPEND _cmake_import_check_files_for_dap_json-c::dap_json-c "${_IMPORT_PREFIX}/lib/libdap_json-c.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
