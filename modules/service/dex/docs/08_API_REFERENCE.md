# DEX v2 C API Reference

## Header File

```c
#include "dap_chain_net_srv_dex.h"
```

---

## Constants

```c
#define DAP_CHAIN_NET_SRV_DEX_ID    0x000000000000000AULL

#define DAP_DEX_FEE_UNIT_NATIVE     10000000000000000ULL   // 0.01 × 10^18
#define DAP_DEX_FEE_STEP_PCT        1000000000000000ULL    // 0.001 × 10^18 (0.1%)
#define DAP_DEX_POW18               1000000000000000000ULL // 1.0 × 10^18
```

---

## Transaction Types

```c
typedef enum dex_tx_type {
    DEX_TX_TYPE_UNDEFINED,
    DEX_TX_TYPE_ORDER,      // New order creation
    DEX_TX_TYPE_EXCHANGE,   // Trade execution (with optional seller residual)
    DEX_TX_TYPE_UPDATE,     // Owner-initiated value modification
    DEX_TX_TYPE_INVALIDATE  // Order cancellation (no SRV_DEX OUT)
} dex_tx_type_t;
```

---

## Order Creation

### Function

```c
dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(
    dap_chain_net_t *a_net,
    const char *a_token_buy,
    const char *a_token_sell,
    uint256_t a_value_sell,
    uint256_t a_rate,
    uint8_t a_min_fill_combined,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx
);
```

### Error Codes

```c
typedef enum dap_chain_net_srv_dex_create_error_list {
    DEX_CREATE_ERROR_OK = 0,
    DEX_CREATE_ERROR_INVALID_ARGUMENT,
    DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND,
    DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND,
    DEX_CREATE_ERROR_PAIR_NOT_ALLOWED,
    DEX_CREATE_ERROR_RATE_IS_ZERO,
    DEX_CREATE_ERROR_FEE_IS_ZERO,
    DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO,
    DEX_CREATE_ERROR_INTEGER_OVERFLOW,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH,
    DEX_CREATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_create_error_t;
```

### min_fill_combined Encoding

```
[bit 7: from_origin] [bits 0-6: percent]

Examples:
  0x00 = PARTIAL_OK (any fill accepted)
  0x32 = MIN 50% of remaining
  0x64 = AON (100% required)
  0xB2 = MIN 50% of original value (from_origin)
```

---

## Order Removal (Invalidation)

### Function

```c
dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_hash,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx
);
```

### Error Codes

```c
typedef enum dap_chain_net_srv_dex_remove_error_list {
    DEX_REMOVE_ERROR_OK = 0,
    DEX_REMOVE_ERROR_INVALID_ARGUMENT,
    DEX_REMOVE_ERROR_FEE_IS_ZERO,
    DEX_REMOVE_ERROR_TX_NOT_FOUND,
    DEX_REMOVE_ERROR_INVALID_OUT,
    DEX_REMOVE_ERROR_NOT_OWNER,
    DEX_REMOVE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_remove_error_t;
```

---

## Order Update

### Function

```c
dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_root,
    bool a_has_new_value,
    uint256_t a_new_value,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx
);
```

### Error Codes

```c
typedef enum dap_chain_net_srv_dex_update_error_list {
    DEX_UPDATE_ERROR_OK = 0,
    DEX_UPDATE_ERROR_INVALID_ARGUMENT,
    DEX_UPDATE_ERROR_NOT_FOUND,
    DEX_UPDATE_ERROR_NOT_OWNER,
    DEX_UPDATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_update_error_t;
```

---

## Single Order Purchase

### Function

```c
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_hash,
    uint256_t a_value,
    bool a_is_budget_buy,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    bool a_create_buyer_order_on_leftover,
    uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx
);
```

`a_value == 0` means unlimited budget (full fill of the specified order).

---

## Multi-Order Purchase

### Function

```c
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_multi(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_hashes,
    size_t a_orders_count,
    uint256_t a_value,
    bool a_is_budget_buy,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    bool a_create_buyer_order_on_leftover,
    uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx
);
```

---

## Auto-Match Purchase

### Function

```c
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_auto(
    dap_chain_net_t *a_net,
    const char *a_sell_token,
    const char *a_buy_token,
    uint256_t a_value,
    bool a_is_budget_buy,
    uint256_t a_fee,
    uint256_t a_rate_cap,
    dap_chain_wallet_t *a_wallet,
    bool a_create_buyer_order_on_leftover,
    uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx,        // Can be NULL for dry-run
);
```

`a_value == 0` means unlimited budget (full fill across matches).

Rate cap semantics: BID skips orders with rate above the cap, ASK skips orders with rate below the cap.

### Dry-Run Mode

When `a_tx == NULL`, the function performs matching only without composing a transaction:
- Builds match table as usual
- Populates `a_matches` if provided
- Does NOT create or sign transaction
- Returns `DEX_PURCHASE_ERROR_OK` on successful matching

---

## Purchase Error Codes

```c
typedef enum dap_chain_net_srv_dex_purchase_error_list {
    DEX_PURCHASE_ERROR_OK = 0,
    DEX_PURCHASE_ERROR_INVALID_ARGUMENT,
    DEX_PURCHASE_ERROR_ORDER_NOT_FOUND,
    DEX_PURCHASE_ERROR_ORDER_SPENT,
    DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY,
    DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH,
    DEX_PURCHASE_MULTI_ERROR_SIDE_MISMATCH,
    DEX_PURCHASE_AUTO_ERROR_NO_MATCHES,
    DEX_PURCHASE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_purchase_error_t;
```

---

## Legacy Migration

### Function

```c
dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_prev_hash,
    uint256_t a_rate_new,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx
);
```

Converts SRV_XCHANGE (DEX v1, subtype 0x02) orders to SRV_DEX (v2, subtype 0x05).
`a_rate_new` is interpreted as legacy XCHANGE price (BUY per SELL) and converted to canonical QUOTE/BASE when needed.

See also: [DEX migration sync](09_MIGRATION_SYNC.md).

### Error Codes

```c
typedef enum dap_chain_net_srv_dex_migrate_error_list {
    DEX_MIGRATE_ERROR_OK = 0,
    DEX_MIGRATE_ERROR_INVALID_ARGUMENT,
    DEX_MIGRATE_ERROR_PREV_NOT_FOUND,
    DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE,
    DEX_MIGRATE_ERROR_NOT_OWNER,
    DEX_MIGRATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_migrate_error_t;
```

---

## Bulk Cancellation

### Function

```c
dap_chain_net_srv_dex_cancel_all_error_t dap_chain_net_srv_dex_cancel_all_by_seller(
    dap_chain_net_t *a_net,
    const dap_chain_addr_t *a_seller,
    const char *a_base_token,
    const char *a_quote_token,
    int a_limit,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx
);
```

### Error Codes

```c
typedef enum dap_chain_net_srv_dex_cancel_all_error_list {
    DEX_CANCEL_ALL_ERROR_OK = 0,
    DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT,
    DEX_CANCEL_ALL_ERROR_WALLET,
    DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY,
    DEX_CANCEL_ALL_ERROR_WALLET_MISMATCH,
    DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CANCEL_ALL_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_cancel_all_error_t;
```

---

## Order Matching API

### Match Hashes Query

```c
dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(
    dap_chain_net_t *a_net,
    const char *a_sell_token,
    const char *a_buy_token,
    dap_chain_net_id_t *a_sell_net_id,
    dap_chain_net_id_t *a_buy_net_id,
    uint256_t *a_max_value,
    uint256_t *a_rate_cap,
    size_t *a_num_matches,
    bool a_is_budget_buy
);
```

Returns array of order tail hashes matching criteria. Caller must free returned array.
Rate cap semantics: BID skips orders with rate above the cap, ASK skips orders with rate below the cap.

---

## CLI Helper: Find Matches

```bash
srv_dex find_matches -net <network_name> -order <hash> -addr <wallet_addr>
```

Preflight match analysis for a legacy or DEX order.  
Accepts any hash in the order chain; resolves to the latest tail.  
Filters out orders owned by the provided address and reports expected pay/receive amounts per match.

---

## Cache Management

### Adjust MinFill (Testing)

```c
int dap_chain_net_srv_dex_cache_adjust_minfill(
    dap_chain_net_t *a_net,
    const dap_hash_fast_t *a_order_tail,
    uint8_t a_new_minfill,
    uint8_t *a_out_old_minfill
);
```

Returns: 0 on success, -1 invalid args, -2 order not found.

### Debug Dumps

```c
void dap_chain_net_srv_dex_dump_orders_cache();
void dap_chain_net_srv_dex_dump_history_cache();
```

---

## Decree Callback

```c
int dap_chain_net_srv_dex_decree_callback(
    dap_ledger_t *a_ledger,
    bool a_apply,
    dap_tsd_t *a_params,
    size_t a_params_size
);
```

---

## Initialization

```c
int dap_chain_net_srv_dex_init();
void dap_chain_net_srv_dex_deinit();
```

---

## OUT_COND Subtype Structure

```c
struct srv_dex {
    dap_chain_net_id_t buy_net_id, sell_net_id;
    char buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_addr_t seller_addr;
    dap_chain_hash_fast_t order_root_hash;  // Zero for new order
    uint256_t rate;                          // Canonical QUOTE/BASE
    uint8_t min_fill;                        // [bit7:from_origin][bits0-6:percent]
    uint8_t version;                         // Payload version
    uint32_t flags;                          // Reserved (currently 0)
    uint8_t tx_type;                         // ORDER/EXCHANGE/UPDATE
    uint8_t _padding[7];
} DAP_ALIGN_PACKED;
```

Subtype code: `DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX = 0x05`

---

## side_version Encoding

Used in cache entries:

```c
uint8_t side_version;
// bit 0: side (0 = ASK, 1 = BID)
// bits 1-7: version from OUT_COND

uint8_t side = side_version & 0x1;
uint8_t version = (side_version >> 1) & 0x7F;
```

---

## ts_expires Handling

Orders can have optional expiration:

```c
// In OUT_COND header:
dap_time_t ts_expires;  // 0 = no expiration

// Verification:
if (l_prev->header.ts_expires && l_now > l_prev->header.ts_expires)
    RET_ERR(DEXV_EXPIRED);

// Matching:
if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
    continue; // Skip expired order
```


