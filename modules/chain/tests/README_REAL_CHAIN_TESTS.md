# Chain Cell Real Chain Integration Tests

## Overview

This test suite validates the `dap_chain_cell_read_atom_by_offset()` functionality with both synthetic test data and real production chain files.

## Features

- ✅ Standard unit tests with synthetic data
- ✅ Integration tests with real production chains
- ✅ Configurable test parameters via command line
- ✅ Support for different cell IDs
- ✅ Adjustable number of random reads

## Building

```bash
cd build
make chain-cell-test -j$(nproc)
```

## Usage

### Standard Unit Tests

Run basic tests with synthetic data (always runs by default):

```bash
./cellframe-sdk/modules/chain/tests/chain-cell-test
```

Output:
```
=== DAP Chain Cell Tests ===
✓ API Verification Test
✓ Write/Read 20 Blocks Test
✓ 30 Transactions Random Access Test
=== All Tests PASSED ===
```

### Real Chain Integration Tests

Test with production chain files:

```bash
./cellframe-sdk/modules/chain/tests/chain-cell-test \
    --real-chain /opt/cellframe-node/var/lib/network/riemann/main
```

#### Command Line Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--real-chain PATH` | Path to chain storage directory | None | `/opt/cellframe-node/var/lib/network/riemann/main` |
| `--cell-id ID` | Cell ID to test (hex format) | 0 | `0`, `1`, `a` |
| `--test-count N` | Number of random reads | 50 | `100`, `500` |
| `--help`, `-h` | Show help message | - | - |

### Examples

#### Test Riemann Main Chain (Cell 0)
```bash
./chain-cell-test --real-chain /opt/cellframe-node/var/lib/network/riemann/main
```

#### Test with More Random Reads
```bash
./chain-cell-test \
    --real-chain /opt/cellframe-node/var/lib/network/riemann/main \
    --test-count 100
```

#### Test Different Cell ID
```bash
./chain-cell-test \
    --real-chain /opt/cellframe-node/var/lib/network/riemann/main \
    --cell-id 1 \
    --test-count 50
```

#### Test Zerochain
```bash
./chain-cell-test \
    --real-chain /opt/cellframe-node/var/lib/network/riemann/zero \
    --test-count 30
```

## What the Tests Do

### Standard Tests

1. **API Verification** - Validates that the function signature exists
2. **Write/Read 20 Blocks** - Creates 20 test blocks and reads them back
3. **30 Transactions Random Access** - Tests random reads of 30 transactions

### Real Chain Tests

1. **File Validation** - Checks if chain file exists and is readable
2. **Sequential Scan** - Scans file to find valid atoms (up to 1000)
3. **Random Access Reads** - Performs random reads from found atoms
4. **Verification** - Compares read sizes with expected sizes

## Test Results Example

```
=== Real Chain Test Results ===
Total atoms found: 1000
Tests performed: 100
Successful reads: 100
Failed reads: 0
Success rate: 100.0%
✓ Real chain test PASSED (success rate >= 95%)
```

## Success Criteria

- Unit tests: All must pass
- Real chain tests: Success rate >= 95%

## Typical Performance

| Chain | File Size | Atoms Found | Test Count | Time |
|-------|-----------|-------------|------------|------|
| Riemann Main | 875 MB | 1000 | 100 | ~2-3 sec |
| Riemann Zero | Variable | Variable | 50 | ~1-2 sec |

## Troubleshooting

### Chain file not found
```
ERROR: Cell file does not exist: /path/to/0.dchaincell
SKIPPING real chain test
```
**Solution**: Check that the path is correct and the node has synced the chain.

### No valid atoms found
```
WARNING: No valid atoms found in file
This might be expected for empty or corrupted chains
```
**Solution**: This is normal for empty chains or chains that are still syncing.

### Low success rate
```
Success rate: 85.0%
WARNING: Success rate below 95% - some reads failed
```
**Solution**: This might indicate:
- Corrupted chain file
- File system issues
- Incorrect file format

## Integration with Wallet Cache

This functionality is used by the wallet cache refactoring to:
1. Store transaction offsets in GlobalDB instead of RAM pointers
2. Read transactions on-demand by file offset
3. Support persistent cache across node restarts

## Files

- `chain_cell_test_main.c` - Main entry point with CLI parsing
- `dap_chain_cell_test.c` - Test implementations
- `include/dap_chain_cell_test.h` - Test function declarations

## Notes

- Real chain tests are **optional** - unit tests always run
- Tests use file-based mode (not memory-mapped) for reliability
- Cell file format: `[37-byte header][size:uint64_t][atom_data]...`
- Scans are limited to first 10,000 atoms for performance
- Test uses deterministic random (seed=12345) for reproducibility

## Author

Olzhas Zharasbaev (DeM Labs Inc.)

## License

GPLv3

