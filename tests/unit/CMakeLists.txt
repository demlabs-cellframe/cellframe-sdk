cmake_minimum_required(VERSION 3.10)

# Unit tests - isolated module tests

# Datum unit tests (structure packing, JSON)
add_subdirectory(datum)

# Ledger unit tests (TX operations, mocking showcase)
add_subdirectory(ledger)

# Service unit tests (voting, stake-ext, etc.)
add_subdirectory(service)
