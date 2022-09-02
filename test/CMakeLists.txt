cmake_minimum_required(VERSION 3.10)
project(sdk_tests C CXX)

set(CMAKE_C_STANDARD 11)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)


include_directories(../modules/common/include)
include_directories(../dap-sdk/core/include)



FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )


include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG main
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()
add_executable(
        256_tests
        256_tests.cc
)
target_link_libraries(
        256_tests
        GTest::gtest_main
        GTest::gtest
        ${Boost_LIBRARIES}
        m
        cellframe-sdk
)
target_include_directories(
        256_tests
        INTERFACE
        ../
)

include(GoogleTest)
gtest_discover_tests(256_tests)

