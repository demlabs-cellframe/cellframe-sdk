# Voting functionality tests

cmake_minimum_required(VERSION 3.10)

project(voting-test)

# Add simple test executable
add_executable(${PROJECT_NAME} test_voting_simple.c)

# Fix uint256_t type issue
target_compile_definitions(${PROJECT_NAME} PRIVATE uint256_t=uint64_t)

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -g
    -O0
)

# Add test to CTest
add_test(
    NAME voting-test
    COMMAND voting-test
) 