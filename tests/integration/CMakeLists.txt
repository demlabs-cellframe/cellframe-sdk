# Integration Tests
#
# Contains subdirectories with integration test suites for various modules.

cmake_minimum_required(VERSION 3.10)

# DEX module integration tests
add_subdirectory(dex)

# UTXO blocking integration tests
add_subdirectory(utxo_blocking)
