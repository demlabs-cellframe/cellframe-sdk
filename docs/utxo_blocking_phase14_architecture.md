# UTXO Blocking History & Arbitrage Transactions - Architecture Analysis

## 🎯 Problem Statement

### Zero Chain vs Main Chain Timing Issue

**Critical Issue:** Token updates (including UTXO blocking/unblocking) appear on **Zero Chain (DAG)** significantly earlier than they appear on **Main Chain (blockchain)**, which is used to determine blockchain time.

#### Current Architecture:
```
Zero Chain (DAG, PoA)
├── Fast consensus (~seconds)
├── Token updates appear here FIRST
└── No blockchain time reference

Main Chain (blockchain, ESBOCS)
├── Slower consensus (~minutes)  
├── Used for blockchain_time calculation
└── Token updates replicated here LATER
```

#### The Problem:
1. Token owner creates `token_update` with UTXO blocking at time T1
2. Update appears on Zero Chain at T1+5 seconds
3. UTXO becomes blocked according to current `s_ledger_utxo_is_blocked()` logic
4. But Main Chain blockchain_time is still at T1-300 seconds!
5. **Result:** Blocking activates BEFORE the blockchain time says it should

### Current Implementation Limitations

#### Single State Model:
```c
typedef struct dap_ledger_utxo_block_item {
    dap_ledger_utxo_block_key_t key;
    dap_time_t blocked_time;           // When added
    dap_time_t becomes_effective;      // When blocking activates
    dap_time_t becomes_unblocked;      // When unblocking happens (0 = never)
    UT_hash_handle hh;
} dap_ledger_utxo_block_item_t;
```

**Problem:** Only stores CURRENT state, not HISTORY of changes!

#### What Happens During Sync:
1. Node downloads Zero Chain → sees UTXO blocked
2. Node downloads Main Chain → blockchain_time advances
3. **Lost information:** When was UTXO blocked? When was it unblocked? What was sequence?

## 🏗️ Proposed Solution

### 1. Full History Storage

Store **ALL changes** to UTXO blocking state, not just current state:

```c
typedef enum dap_ledger_utxo_block_action {
    BLOCK_ACTION_ADD = 1,      // UTXO was blocked
    BLOCK_ACTION_REMOVE = 2,   // UTXO was unblocked
    BLOCK_ACTION_CLEAR = 3     // All UTXOs cleared for token
} dap_ledger_utxo_block_action_t;

typedef struct dap_ledger_utxo_block_history_item {
    dap_ledger_utxo_block_action_t action;  // What happened
    dap_time_t bc_time;                      // Blockchain time when it happened
    dap_hash_fast_t token_update_hash;       // Which token_update caused this
    
    // Double-linked list for chronological ordering
    struct dap_ledger_utxo_block_history_item *next;
    struct dap_ledger_utxo_block_history_item *prev;
} dap_ledger_utxo_block_history_item_t;
```

### 2. Enhanced UTXO Block Item

```c
typedef struct dap_ledger_utxo_block_item {
    dap_ledger_utxo_block_key_t key;  // tx_hash + out_idx
    
    // Current state (for fast lookup)
    dap_time_t blocked_time;
    dap_time_t becomes_effective;
    dap_time_t becomes_unblocked;
    
    // NEW: Full history
    dap_ledger_utxo_block_history_item_t *history_head;
    dap_ledger_utxo_block_history_item_t *history_tail;
    pthread_rwlock_t history_rwlock;  // Separate lock for history
    
    UT_hash_handle hh;
} dap_ledger_utxo_block_item_t;
```

### 3. State Reconstruction Function

```c
/**
 * @brief Get UTXO blocking state at specific blockchain time
 * @details Walks history chronologically up to specified time
 * @param a_token_item Token containing UTXO blocklist
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @param a_blockchain_time Time to query state at
 * @return true if UTXO was blocked at that time, false otherwise
 */
bool s_ledger_utxo_block_get_state_at_time(
    dap_ledger_token_item_t *a_token_item,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_time_t a_blockchain_time
);
```

#### Algorithm:
1. Find UTXO in hash table
2. If no history → return current state (backward compatibility!)
3. Walk history from head to tail
4. For each item with `bc_time <= a_blockchain_time`:
   - If `BLOCK_ACTION_ADD` → mark as blocked
   - If `BLOCK_ACTION_REMOVE` → mark as unblocked
   - If `BLOCK_ACTION_CLEAR` → mark as unblocked
5. Return final state

### 4. Backward Compatibility (Transparent!)

**No migration needed** - function is still in development, no bans exist yet.

```c
// In s_ledger_utxo_block_get_state_at_time():
if (!l_item->history_head) {
    // Fallback to current state if no history
    return (l_item->becomes_effective <= a_blockchain_time) &&
           (l_item->becomes_unblocked == 0 || l_item->becomes_unblocked > a_blockchain_time);
}
```

## 🔐 Arbitrage Transactions

### Purpose
Allow token owners to reclaim **ANY** output (even blocked ones) in emergency situations.

### Design Decisions

#### ❌ NOT Creating New Condition Type
We are **NOT** creating `DAP_CHAIN_TX_OUT_COND_TYPE_ARBITRAGE` because:
- Adds complexity to transaction validation
- Requires changes to many existing functions
- Harder to implement rate limiting

#### ✅ Using Transaction Marker/TSD
Instead, mark transaction as arbitrage via:
- **Option A:** Add `bool is_arbitrage` field to `dap_chain_datum_tx_t` (if space available)
- **Option B:** Use TSD section with type `DAP_CHAIN_DATUM_TX_TSD_TYPE_ARBITRAGE`

### Validation Flow

```c
// In s_ledger_tx_add_check():
bool l_is_arbitrage = s_ledger_tx_is_arbitrage(l_tx);

if (l_is_arbitrage) {
    // 1. Check token owner signature
    if (!s_ledger_tx_check_arbitrage_auth(l_tx, l_token_item)) {
        return DAP_LEDGER_TX_CHECK_ARBITRAGE_AUTH_FAILED;
    }
    
    // 2. Check rate limiting
    if (!s_ledger_tx_check_arbitrage_rate_limit(l_token_item, l_tx_signer)) {
        return DAP_LEDGER_TX_CHECK_ARBITRAGE_RATE_LIMIT_EXCEEDED;
    }
    
    // 3. BYPASS all these checks:
    // - UTXO blocking checks
    // - Conditional output checks  
    // - Address sender/receiver ban-lists
    
    log_it(L_WARNING, "Arbitrage transaction by token owner for %s", l_token_ticker);
}
```

### Rate Limiting

**Critical:** Prevent abuse of arbitrage mechanism.

```c
#define ARBITRAGE_TX_RATE_LIMIT_PER_HOUR 10

typedef struct dap_ledger_arbitrage_rate_limit {
    dap_pkey_t owner_key;          // Token owner public key
    dap_time_t window_start;        // Rate limit window start
    uint32_t tx_count_in_window;    // Transactions in current window
    UT_hash_handle hh;
} dap_ledger_arbitrage_rate_limit_t;
```

### Default Behavior

**Arbitrage is ENABLED by default** for all CF20 tokens (opt-out model).

To disable:
```bash
# In token_create or token_update:
-flags ARBITRAGE_TX_DISABLED
```

## 🔒 Irreversible Flags

### Problem
Once set, these flags should NEVER be cleared:
- `UTXO_BLOCKING_DISABLED` (BIT 16)
- `ARBITRAGE_TX_DISABLED` (BIT 20)

### Implementation

```c
#define IRREVERSIBLE_TOKEN_FLAGS \
    (DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED | \
     DAP_CHAIN_DATUM_TOKEN_FLAG_ARBITRAGE_TX_DISABLED)

// In s_token_add_check() for token_update:
uint32_t l_old_irreversible = l_token_old->flags & IRREVERSIBLE_TOKEN_FLAGS;
uint32_t l_new_irreversible = l_token_new->flags & IRREVERSIBLE_TOKEN_FLAGS;

if (l_new_irreversible < l_old_irreversible) {
    log_it(L_WARNING, "Attempt to clear irreversible flag for token %s by %s",
           l_token_ticker, l_update_signer);
    return DAP_LEDGER_TOKEN_UPDATE_INVALID; // Reject!
}
```

## 📊 Memory Management

### History Cleanup Strategy

**Problem:** History can grow indefinitely.

**Solution:** Periodic cleanup of old history (keep last N days):

```c
#define UTXO_HISTORY_RETENTION_DAYS 365  // Keep 1 year

void s_ledger_utxo_history_cleanup(dap_ledger_t *a_ledger) {
    dap_time_t l_cutoff_time = dap_ledger_get_blockchain_time(a_ledger) - 
                                (UTXO_HISTORY_RETENTION_DAYS * 86400);
    
    // For each token...
    // For each UTXO...
    // Walk history and delete items older than cutoff
    // BUT: Keep at least last state for auditing!
}
```

### Performance Considerations

- History stored in **RAM** for fast access
- Sorted chronologically for efficient replay
- Separate RW lock to avoid blocking main blocklist operations

## 🔄 Synchronization Flow

### Normal Operation (Node Synced)
```
1. Token update arrives → Zero Chain
2. Parse TSD → Extract UTXO block/unblock
3. Add to history with blockchain_time from Main Chain
4. Update current state
```

### Cold Start (Node Syncing)
```
1. Download Zero Chain → Get all token updates
2. Parse all UTXO block/unblock events
3. Build full history for each UTXO
4. Download Main Chain → Get blockchain_time progression
5. Apply history replay at each blockchain_time checkpoint
6. Final state matches current blockchain_time
```

## 🎯 Success Criteria

1. ✅ History correctly reconstructs state at any blockchain time
2. ✅ Zero Chain / Main Chain sync issues resolved
3. ✅ Arbitrage transactions work only for token owners
4. ✅ Rate limiting prevents arbitrage abuse
5. ✅ Irreversible flags cannot be cleared
6. ✅ Backward compatibility is transparent (no migration)
7. ✅ Performance acceptable with 10K+ history items per UTXO
8. ✅ Memory usage bounded by retention policy

## 📝 Implementation Order

1. **Phase 14.1** ✅ Architecture analysis (this document)
2. **Phase 14.2:** Implement history structures and replay
3. **Phase 14.3:** Implement arbitrage transactions
4. **Phase 14.4:** Implement irreversible flags enforcement
5. **Phase 14.5:** Extend CLI for history/arbitrage
6. **Phase 14.6:** Comprehensive testing
7. **Phase 14.7:** Integration and documentation

---
**Document Status:** Draft for Phase 14.1  
**Last Updated:** 2025-10-17  
**Reviewer:** TBD

