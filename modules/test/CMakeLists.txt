cmake_minimum_required(VERSION 3.10)
if(TARGET dap_test)
    return() # The project has already been built.
endif()
project(dap_test)

add_library(${PROJECT_NAME} STATIC dap_test.h dap_test.c dap_test_generator.h dap_test_generator.c)

target_include_directories(dap_test INTERFACE .)
