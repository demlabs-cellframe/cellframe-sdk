# Wallet Cache Database Schema

## Overview

This document describes the GlobalDB schema for wallet cache storage, replacing the previous RAM-based uthash implementation.

## Architecture

### Previous (RAM-based):
```
Static Global Variable: s_wallets_cache (uthash)
  └─> dap_wallet_cache_t (per wallet)
       ├─> wallet_txs (uthash of transactions) → IN RAM
       └─> unspent_outputs (uthash) → IN RAM
```

### New (GlobalDB-based):
```
GlobalDB Groups (per network + chain)
  └─> Keys (per wallet address)
       ├─> Serialized wallet cache data
       ├─> Transaction metadata with file offsets
       └─> Unspent outputs with file locations
```

## GlobalDB Structure

### Group Naming Convention

**Format:** `wallet.cache.{net_id_hex}.{chain_name}`

**Examples:**
- `wallet.cache.0x0000000000000001.zerochain`
- `wallet.cache.0x0000000000000002.tokchain`

**Benefits:**
- ✅ Isolated by network
- ✅ Isolated by chain
- ✅ Easy to purge cache for specific chain
- ✅ Supports multiple networks simultaneously

### Key Naming Convention

**Format:** `{wallet_address_hex}`

**Example:** `MsECBr5XjH9vDuCbmBYvp6v2kU5T67tPvmfhE1BPUaLz5qx3gczfZtNJn5AWZ5oU`

**Benefits:**
- ✅ Direct lookup by wallet address
- ✅ Human-readable
- ✅ Supports base58 encoding

## Data Structures

### 1. Main Record: `dap_wallet_cache_db_t`

```c
struct dap_wallet_cache_db {
    uint32_t version;                    // Schema version (current: 1)
    dap_chain_addr_t wallet_addr;        // Wallet address
    dap_chain_net_id_t net_id;           // Network ID
    dap_chain_id_t chain_id;             // Chain ID
    
    uint32_t tx_count;                   // Number of cached transactions
    uint32_t unspent_count;              // Number of unspent outputs
    
    dap_time_t last_update;              // Last cache update timestamp
    
    // Variable-length data follows:
    // - Transaction array
    // - Unspent outputs array
};
```

**Size:** ~80 bytes + variable data

### 2. Transaction Record: `dap_wallet_tx_cache_db_t`

```c
struct dap_wallet_tx_cache_db {
    dap_hash_fast_t tx_hash;             // Transaction hash (32 bytes)
    dap_hash_fast_t atom_hash;           // Atom/block hash (32 bytes)
    
    // FILE LOCATION (replaces pointer!)
    dap_chain_cell_id_t cell_id;        // Cell ID (8 bytes)
    off_t file_offset;                   // File offset (8 bytes)
    size_t tx_size;                      // Transaction size (8 bytes)
    
    char token_ticker[10];               // Token ticker
    bool multichannel;                   // Multiple tokens flag
    int ret_code;                        // Ledger check result
    dap_chain_srv_uid_t srv_uid;         // Service UID
    uint32_t action;                     // Action type
    
    uint16_t inputs_count;               // Number of inputs
    uint16_t outputs_count;              // Number of outputs
    
    // Followed by:
    // - Input array
    // - Output array
};
```

**Size per TX:** ~120 bytes + inputs + outputs

**Key Innovation:** 🚀
- **OLD:** `dap_chain_datum_tx_t *tx` (8 bytes pointer → data lost on restart)
- **NEW:** `cell_id + file_offset + size` (24 bytes → persistent, can read from file!)

### 3. Unspent Output Record: `dap_wallet_unspent_out_db_t`

```c
struct dap_wallet_unspent_out_db {
    dap_hash_fast_t tx_hash;             // Transaction hash
    int out_idx;                         // Output index
    
    // FILE LOCATION for fast access
    dap_chain_cell_id_t cell_id;        // Cell ID
    off_t file_offset;                   // File offset to transaction
    size_t tx_size;                      // Transaction size
    
    uint8_t out_type;                    // Output type
    char token_ticker[10];               // Token ticker
    uint256_t value;                     // Output value
};
```

**Size per output:** ~100 bytes

**Critical for:** Creating new transactions (need to find unspent outputs fast!)

## Storage Flow

### Write Operation

```
1. Wallet activity detected (new transaction)
   ↓
2. Build cache record in memory
   ├─> Add transaction metadata
   ├─> Store cell_id + file_offset (from iterator!)
   └─> Update unspent outputs
   ↓
3. Serialize to binary blob
   ↓
4. dap_global_db_set_sync(group, key, blob, size, false)
   ↓
5. Stored in persistent database
```

### Read Operation

```
1. Need wallet transactions
   ↓
2. Generate group and key
   ↓
3. blob = dap_global_db_get_sync(group, key, &size, ...)
   ↓
4. Deserialize blob to structures
   ↓
5. Access transaction data:
   - Read from cell file using cell_id + offset
   - Or use cached metadata
```

## Example Data Layout

```
GlobalDB Group: "wallet.cache.0x01.zerochain"
Key: "MsECBr5XjH9vDuCbmBYvp6v2kU5T67tPvmfhE1BPUaLz5qx3gczfZtNJn5AWZ5oU"

Value (binary blob):
┌──────────────────────────────────────┐
│ dap_wallet_cache_db_t                │
│  - version: 1                        │
│  - wallet_addr: ...                  │
│  - tx_count: 5                       │
│  - unspent_count: 3                  │
│  - last_update: 1735689600           │
├──────────────────────────────────────┤
│ Transaction #1                        │
│  - tx_hash: 0xABCD...                │
│  - cell_id: 0x0001                   │
│  - file_offset: 4096                 │
│  - tx_size: 512                      │
│  - token: "CELL"                     │
│  - inputs_count: 2                   │
│  - outputs_count: 1                  │
│    ├─> Input #1 (prev_hash, idx, value)
│    ├─> Input #2 (prev_hash, idx, value)
│    └─> Output #1 (idx, type)        │
├──────────────────────────────────────┤
│ Transaction #2                        │
│  ...                                  │
├──────────────────────────────────────┤
│ ... (transactions 3-5)                │
├──────────────────────────────────────┤
│ Unspent Output #1                    │
│  - tx_hash: 0x1234...                │
│  - out_idx: 0                        │
│  - cell_id: 0x0001                   │
│  - file_offset: 8192                 │
│  - value: 1000000000                 │
│  - token: "CELL"                     │
├──────────────────────────────────────┤
│ ... (unspent outputs 2-3)            │
└──────────────────────────────────────┘
```

## Performance Characteristics

### Memory Usage (per wallet with 100 transactions, 50 unspent outputs)

**OLD (RAM-based):**
- ~15 KB base structures
- ~100 TX × 200 bytes ≈ 20 KB
- ~50 unspent × 100 bytes ≈ 5 KB
- **Total: ~40 KB IN RAM (lost on restart)**

**NEW (GlobalDB-based):**
- ~80 bytes header
- ~100 TX × 120 bytes ≈ 12 KB
- ~50 unspent × 100 bytes ≈ 5 KB
- **Total: ~17 KB ON DISK (persistent!)**
- **In RAM: Only structures being used (lazy loading)**

### Access Patterns

| Operation | OLD (RAM) | NEW (GlobalDB) |
|-----------|-----------|----------------|
| Find TX by hash | O(1) uthash | O(1) + DB read |
| Get unspent outs | O(n) iterate | O(1) + DB read |
| Wallet load time | Instant (if cached) | ~1-5ms DB read |
| Memory per wallet | 40 KB always | 0 (until accessed) |
| Persistence | ❌ Lost on restart | ✅ Persistent |

## Migration Strategy

### Phase 1: Parallel Mode (Development)
- Keep RAM cache working
- Write to GlobalDB in parallel
- Read from RAM cache
- **Goal:** Test new schema without breaking existing

### Phase 2: Read-Through Cache (Testing)
- Read from GlobalDB first
- Fall back to building from chain if missing
- Write updates to GlobalDB
- **Goal:** Validate DB performance

### Phase 3: Full Migration (Production)
- Remove RAM uthash structures
- All operations through GlobalDB
- **Goal:** Production deployment

## Benefits Summary

✅ **Persistent:** Data survives node restart
✅ **Memory efficient:** Only active wallets in RAM
✅ **Scalable:** Can handle millions of wallets
✅ **File-based:** No need to store full transactions
✅ **Fast:** Direct file offset access
✅ **Maintainable:** Clear schema with versioning

## Notes for Implementation

1. **Transaction data is NOT stored** - only metadata + file location
2. **File offset must be updated** when chain reorganization happens
3. **Unspent outputs** are the most critical - must be fast to access
4. **Cache invalidation** - delete DB entry when wallet is updated
5. **Compression** - Consider compressing large blobs (>10KB)
6. **TTL** - Old wallet cache entries could have TTL for cleanup

## Future Enhancements

- [ ] Add LRU cache in RAM for hot wallets
- [ ] Implement incremental updates (append-only)
- [ ] Add compression for large wallet caches
- [ ] Support partial cache (only recent N transactions)
- [ ] Add statistics (cache hit rate, size, etc.)
