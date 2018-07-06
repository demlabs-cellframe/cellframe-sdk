cmake_minimum_required(VERSION 2.8)

project(libdap-test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tell CMake to run moc when necessary:
set(CMAKE_AUTOMOC ON)

# As moc files are generated in the binary dir, tell CMake
# to always look for includes there:
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5Test REQUIRED)

# dependencies for testing

set(HEADERS
    ../core/dap_config.h
    ../core/dap_common.h
    )

set(SRC
    ../core/dap_config.c
    ../core/dap_common.c
    )

set(TEST_FILES
    main.cpp
    TestHeaders.hpp
    core/DapConfig_test.hpp
)

add_executable(${PROJECT_NAME} ${TEST_FILES} ${SRC} ${HEADERS}) # ${SRC} ${HEADERS}

target_include_directories(${PROJECT_NAME} PUBLIC ../core)
target_link_libraries(${PROJECT_NAME} Qt5::Test)

