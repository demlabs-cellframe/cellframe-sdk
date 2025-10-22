# UTXO Flags Migration to TSD Section

**Date:** 2025-10-22  
**Status:** ✅ COMPLETED  
**Impact:** BREAKING CHANGE (no backward compatibility)

## 📋 Overview

UTXO-related flags have been migrated from `header_native_decl.flags` (uint16_t) to a dedicated TSD section `UTXO_FLAGS` (0x002D, uint32_t). This architectural change fixes the uint16_t overflow issue where flags defined with BIT(16+) were silently ignored.

## 🔴 Problem Statement

### Before Migration

UTXO flags were defined in `dap_chain_datum_token.h` as:

```c
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST         BIT(17)  // 0x20000
#define DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_SENDER_BLOCKING  BIT(18)  // 0x40000
```

**Critical Issue:** These flags overflowed `header_native_decl.flags` (uint16_t, max 0xFFFF):
- BIT(16) = 65536 → overflows to 0 when stored in uint16_t
- BIT(17) = 131072 → overflows to 0 when stored in uint16_t
- Compiler warning: "unsigned conversion changes value from 65536 to 0"

**Real-world Impact:**
- `UTXO_BLOCKING_DISABLED` flag was silently ignored
- Testers couldn't verify functionality (reported as bug)
- Token creators couldn't opt-out of UTXO blocking

## ✅ Solution: TSD Section Migration

### Architecture

1. **New TSD Type:** `DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS` = 0x002D
2. **Storage Format:** [utxo_flags: 4 bytes (uint32_t)]
3. **Location:** Token datum TSD section (alongside other TSDs)
4. **Flags Renumbered:** BIT(0-4) instead of BIT(16-20) for TSD storage

### New Flag Names (with UTXO_ prefix for clarity)

All UTXO-related flags have been renamed with `UTXO_` prefix:

| Old Name (DEPRECATED) | New Name | Bit | Value |
|----------------------|----------|-----|-------|
| `STATIC_UTXO_BLOCKLIST` | `DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST` | BIT(1) | 0x02 |
| `DISABLE_ADDRESS_SENDER_BLOCKING` | `DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING` | BIT(2) | 0x04 |
| `DISABLE_ADDRESS_RECEIVER_BLOCKING` | `DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_RECEIVER_BLOCKING` | BIT(3) | 0x08 |
| `ARBITRAGE_TX_DISABLED` | `DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED` | BIT(4) | 0x10 |
| *(new)* | `DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED` | BIT(0) | 0x01 |

**Note:** Old names are **NOT supported** (no backward compatibility by design).

## 🔧 Implementation Changes

### 1. Token Datum Structure

**Before:**
```c
typedef struct dap_chain_datum_token_t {
    // ...
    struct {
        uint16_t flags;  // ← Overflow here!
        // ...
    } header_native_decl;
    // ...
} dap_chain_datum_token_t;
```

**After:**
```c
// Flags now in TSD:
typedef struct dap_chain_datum_token_t {
    // ...
    struct {
        uint16_t flags;  // Only non-UTXO flags
        size_t tsd_total_size;
        // ...
    } header_native_decl;
    byte_t tsd_n_signs[];  // ← UTXO flags stored here in TSD
} dap_chain_datum_token_t;
```

### 2. CLI Parser Changes

**Token Declaration:**
```bash
# CLI automatically creates UTXO_FLAGS TSD when UTXO flags are used
token_decl -net mynet -token TEST -flags UTXO_BLOCKING_DISABLED -certs owner
```

**Token Update:**
```bash
# CLI automatically creates UTXO_FLAGS TSD for flag changes
token_update -net mynet -token TEST -flag_set UTXO_STATIC_BLOCKLIST -certs owner
```

**Implementation:** `dap_chain_node_cli_cmd.c:s_parse_additional_token_decl_arg()`
- Detects UTXO flags via `dap_chain_datum_token_utxo_flag_from_str()`
- Creates TSD section `UTXO_FLAGS` with uint32_t value
- Rejects attempts to unset UTXO flags (they are irreversible)

### 3. Ledger TSD Parser

**Location:** `dap_chain_ledger.c`

**New Case in TSD Parser:**
```c
case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS: {
    if (l_tsd->size != sizeof(uint32_t)) {
        return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
    }
    uint32_t l_utxo_flags = dap_tsd_get_scalar(l_tsd, uint32_t);
    a_item_apply_to->flags |= l_utxo_flags;  // Merge into token_item->flags
    break;
}
```

### 4. Irreversible Flags Validation

**Location:** `dap_chain_ledger.c:s_token_add_check()`

**Updated Logic:**
- Extracts UTXO flags from TSD in token_update datum
- If UTXO_FLAGS TSD is absent, inherits old UTXO flags (no change)
- Validates: `new_irreversible_flags >= old_irreversible_flags`
- Prevents unsetting UTXO flags (one-way operation)

## 📝 Migration Guide for Developers

### If You're Creating Tokens

**Old Code (Will NOT work):**
```bash
token_decl -flags STATIC_UTXO_BLOCKLIST  # ❌ Old name
```

**New Code:**
```bash
token_decl -flags UTXO_STATIC_BLOCKLIST  # ✅ New name
```

### If You're Reading Tokens

**Old Code:**
```c
// ❌ Wrong: Reading from header
uint16_t flags = token_datum->header_native_decl.flags;
if (flags & DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST) { ... }
```

**New Code:**
```c
// ✅ Correct: Reading from token_item (ledger merges TSD flags)
dap_ledger_token_item_t *token_item = dap_ledger_token_ticker_check(ledger, "MYTOKEN");
if (token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) { ... }
```

**For Direct TSD Parsing:**
```c
// Parse TSD section to extract UTXO flags
dap_tsd_t *tsd = (dap_tsd_t *)token_datum->tsd_n_signs;
for (size_t offset = 0; offset < tsd_total_size; offset += dap_tsd_size(tsd)) {
    if (tsd->type == DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS) {
        uint32_t utxo_flags = *(uint32_t*)tsd->data;
        break;
    }
    tsd = (dap_tsd_t *)((byte_t*)tsd + dap_tsd_size(tsd));
}
```

## 🧪 Testing

### Test Coverage

1. **Unit Tests:** `utxo_blocking_unit_test.c`
   - ✅ Flag name conversions
   - ✅ Irreversible mask validation

2. **Integration Tests:** `utxo_blocking_integration_test.c`
   - ✅ Test 6: `UTXO_BLOCKING_DISABLED` behavior
   - ✅ Manual TSD creation with UTXO flags
   - ✅ Verification of flag enforcement

3. **CLI Integration Tests:** `utxo_blocking_cli_integration_test.c`
   - ✅ CLI command workflow with UTXO flags
   - ✅ Flag setting via `token_decl` and `token_update`

### Test Results

```
Test project /home/naeper/work/cellframe-node/cellframe-sdk/build
    Start 1: utxo_blocking_unit
1/3 Test #1: utxo_blocking_unit ...............   Passed    0.01 sec
    Start 2: utxo_blocking_integration
2/3 Test #2: utxo_blocking_integration ........   Passed    0.04 sec
    Start 3: utxo_blocking_cli_integration
3/3 Test #3: utxo_blocking_cli_integration ....   Passed    0.05 sec

100% tests passed, 0 tests failed out of 3
```

## 🔒 Backward Compatibility

**BREAKING CHANGE:** NO backward compatibility

- Old flag names are **not supported**
- Old tokens with flags in header will continue to work (flags < BIT(16))
- New tokens MUST use new flag names
- Migration script NOT provided (clean break by design)

**Rationale:**
- Clean architecture without legacy baggage
- Prevents confusion between old/new flag systems
- Forces explicit adoption of correct flag usage

## 📊 Benefits

### Before (Problems)
- ❌ uint16_t overflow (BIT 16+ silently ignored)
- ❌ Compiler warnings about truncation
- ❌ Flags couldn't be tested by QA
- ❌ Limited to 16 flag bits

### After (Solutions)
- ✅ No overflow (uint32_t storage, 32 flag bits available)
- ✅ No compiler warnings
- ✅ Flags work as documented
- ✅ Clear separation of UTXO flags (via UTXO_ prefix)
- ✅ Extensible (room for 28 more UTXO flags)

## 🚀 Deployment

### Files Changed

**Core Implementation:**
- `cellframe-sdk/modules/common/include/dap_chain_datum_token.h` - Flag definitions
- `cellframe-sdk/modules/common/dap_chain_datum_token.c` - String conversion functions
- `cellframe-sdk/modules/net/dap_chain_node_cli_cmd.c` - CLI parser
- `cellframe-sdk/modules/net/dap_chain_ledger.c` - TSD parser + validation

**Tests:**
- `cellframe-sdk/tests/unit/utxo_blocking_unit_test.c` - Updated flag names
- `cellframe-sdk/tests/integration/utxo_blocking_integration_test.c` - Test 6 rewritten
- `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c` - CLI workflow

**Documentation:**
- `cellframe-sdk/docs/UTXO_BLOCKING_EXAMPLES.md` - Updated examples
- `cellframe-sdk/docs/UTXO_VERIFICATION_REPORT.md` - Updated verification
- `cellframe-sdk/docs/UTXO_100_PERCENT_COVERAGE_PLAN.md` - Updated plan
- `cellframe-sdk/docs/README_UTXO_SCRIPTS.md` - Updated scripts
- `cellframe-sdk/docs/verify_utxo_cli_commands.sh` - Updated checks
- `cellframe-sdk/docs/UTXO_FLAGS_TSD_MIGRATION.md` - This document

### Deployment Steps

1. ✅ Update SDK code (core, CLI, ledger)
2. ✅ Update all tests
3. ✅ Verify 100% test pass rate
4. ✅ Update documentation
5. ⏭️ Release notes mentioning BREAKING CHANGE
6. ⏭️ Update developer guides
7. ⏭️ Notify token issuers about flag name changes

## 📞 Support

### Common Issues

**Q: My old flag `STATIC_UTXO_BLOCKLIST` doesn't work**  
**A:** Use new name: `UTXO_STATIC_BLOCKLIST`

**Q: Can I mix old and new flag names?**  
**A:** No. Old names are not recognized. Update all code to new names.

**Q: How do I read UTXO flags from token datum?**  
**A:** Use `dap_ledger_token_ticker_check()` to get `token_item`, then read `token_item->flags`. Ledger automatically merges TSD flags.

**Q: Can UTXO flags be unset?**  
**A:** No. UTXO flags are irreversible (security feature).

## 📚 Related Documents

- [UTXO_BLOCKING_EXAMPLES.md](UTXO_BLOCKING_EXAMPLES.md) - Updated usage examples
- [UTXO_VERIFICATION_REPORT.md](UTXO_VERIFICATION_REPORT.md) - Test coverage report
- [UTXO_100_PERCENT_COVERAGE_PLAN.md](UTXO_100_PERCENT_COVERAGE_PLAN.md) - Testing plan

---

**Migration Completed:** 2025-10-22  
**All Tests Passing:** ✅ 100%  
**Status:** PRODUCTION READY

