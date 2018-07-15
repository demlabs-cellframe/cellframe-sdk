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

file(GLOB TEST_FILES *.hpp *.cpp core/*.hpp)
add_executable(${PROJECT_NAME} ${TEST_FILES} ${SRC} ${HEADERS})

target_link_libraries(${PROJECT_NAME} Qt5::Test)
target_link_libraries(${PROJECT_NAME} dap_core)
target_link_libraries(${PROJECT_NAME} dap_crypto)

add_test(
    NAME libdap-test
    COMMAND libdap-test
)
