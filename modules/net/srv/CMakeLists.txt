cmake_minimum_required(VERSION 3.10)

# Network Services - srv (contains base + stake common types + other services)
# Base MUST be first
add_subdirectory(base)

# Stake common types (header-only library with common stake types)
add_subdirectory(stake)

