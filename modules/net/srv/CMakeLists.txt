cmake_minimum_required(VERSION 3.10)

# Network Services - srv (contains base + stake + other services)
# Base MUST be first
add_subdirectory(base)

# Other services
# TODO: Fix stake after decree refactoring
#add_subdirectory(stake)

