# DEX v2 Transaction Verification

## Overview

The verificator (`s_dex_verificator_callback`) validates SRV_DEX transactions before ledger acceptance. Runs in two contexts:

1. **Consensus** — Full validation for new TXs
2. **Replay** — Lightweight validation on node restart

---

## Verification Phases

### Phase 0: Pre-Scan

Iterate TX items to:
- Count IN_COND items
- Locate single SRV_DEX OUT_COND
- Count regular OUTs (for payout validation)

```c
// Enforce single SRV_DEX OUT
if (l_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
    if (l_out_cond)
        RET_ERR(DEXV_MULTIPLE_SRV_DEX_OUT);
    l_out_cond = l_out;
}
```

### Phase 1: Type Classification

| IN_COND Count | OUT_COND | Type |
|---------------|----------|------|
| 0 | Yes (root=blank) | ORDER |
| 1+ | Yes (root=set, owner) | UPDATE |
| 1+ | Yes (root=set, !owner) | EXCHANGE |
| 1+ | No | INVALIDATE |

```c
switch (l_in_cond_cnt) {
case 0:
    // Must be ORDER with blank root
    if (!l_out_cond || l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_ORDER)
        RET_ERR(DEXV_TX_TYPE_MISMATCH);
    break;
case 1:
    // UPDATE requires owner signature + declared tx_type
    if (l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE && !a_owner)
        RET_ERR(DEXV_TX_TYPE_MISMATCH);
    break;
}
```

### Phase 2: Baseline Extraction

From first IN_COND, extract:
- Sell token ticker
- Buy token ticker
- Network IDs
- Order side (ASK/BID)

```c
const char *l_sell_cur = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in->header.tx_prev_hash);
l_sell_ticker = l_sell_cur;
l_buy_ticker = l_prev->subtype.srv_dex.buy_token;
l_sell_net_id = l_prev->subtype.srv_dex.sell_net_id;
l_buy_net_id = l_prev->subtype.srv_dex.buy_net_id;
```

### Phase 3: Consistency Validation

For multi-IN_COND TXs, verify:
- All INs have same token pair
- All INs have same side (ASK/BID)
- All INs from whitelisted pair

```c
dap_do_if_any(RET_ERR(DEXV_BASELINE_TUPLE),
    strcmp(l_buy_ticker, l_prev->subtype.srv_dex.buy_token),
    strcmp(l_sell_ticker, l_sell_cur),
    l_sell_net_id.uint64 != l_prev->subtype.srv_dex.sell_net_id.uint64,
    l_buy_net_id.uint64 != l_prev->subtype.srv_dex.buy_net_id.uint64);
```

### Phase 4: Payout Validation

Verify seller receives exact expected amount in buy token:

```c
expected_buy = executed_sell × rate
if (compare256(l_seller->paid_buy, l_seller->expected_buy) != 0)
    RET_ERR(DEXV_SELLER_PAYOUT_MISMATCH);
```

### Phase 5: Fee Validation

- Network fee: must meet minimum
- Service fee: must meet configured amount (native or percent)
- Validator fee: must be present in FEE OUT_COND

---

## Error Codes

```c
typedef enum {
    DEXV_OK,
    DEXV_INVALID_PARAMS,
    DEXV_INVALID_TX_ITEM,
    DEXV_MULTIPLE_SRV_DEX_OUT,
    DEXV_NO_IN,
    DEXV_PREV_TX_NOT_FOUND,
    DEXV_PREV_OUT_NOT_FOUND,
    DEXV_EXPIRED,
    DEXV_BASELINE_BUY_TOKEN,
    DEXV_BASELINE_TUPLE,
    DEXV_PAIR_NOT_ALLOWED,
    DEXV_INVALID_FEE_CONFIG,
    DEXV_SERVICE_FEE_ADDR_BLANK,
    DEXV_INVALID_RESIDUAL,
    DEXV_MIN_FILL_AON,
    DEXV_MIN_FILL_NOT_REACHED,
    DEXV_TX_TYPE_MISMATCH,
    DEXV_IMMUTABLES_VIOLATION,
    DEXV_SERVICE_FEE_UNDERPAID,
    DEXV_FEE_NOT_FROM_BUYER,
    DEXV_SERVICE_FEE_MISMATCH,
    DEXV_NETWORK_FEE_UNDERPAID,
    DEXV_BUY_TOKEN_LEAK,
    DEXV_SELL_TOKEN_LEAK,
    DEXV_SELLER_PAID_IN_UPDATE,
    DEXV_SELLER_PAYOUT_MISMATCH,
    DEXV_BUYER_ADDR_MISSING,
    DEXV_BUYER_MISMATCH,
    DEXV_SELF_PURCHASE,
    DEXV_MULTI_BUYER_DEST,
    DEXV_FINAL_NATIVE_MISMATCH,
    DEXV_FINAL_NONNATIVE_MISMATCH,
    DEXV_REFUND_MISMATCH,
    DEXV_BUYER_PAYOUT_ADDR_MISMATCH,
    DEXV_INVALIDATE_MULTI_SELLER,
    DEXV_INVALIDATE_NOT_OWNER,
    DEXV_UPDATE_NOT_OWNER,
    DEXV_LEFTOVER_STRUCTURE_VIOLATION,
    DEXV_ROOT_CHAIN_MISMATCH,
    DEXV_CANONICAL_LEFTOVER_MISMATCH
} dex_verif_code_t;
```

---

## Error Categories

### Structural Errors

| Code | Cause |
|------|-------|
| `DEXV_INVALID_TX_ITEM` | Unknown TX item type |
| `DEXV_MULTIPLE_SRV_DEX_OUT` | More than one SRV_DEX OUT_COND |
| `DEXV_PREV_TX_NOT_FOUND` | Referenced TX not in ledger |
| `DEXV_PREV_OUT_NOT_FOUND` | Previous TX lacks SRV_DEX OUT |
| `DEXV_INVALID_RESIDUAL` | Zero value or rate in residual |

### Type Errors

| Code | Cause |
|------|-------|
| `DEXV_TX_TYPE_MISMATCH` | Declared type doesn't match structure |
| `DEXV_UPDATE_NOT_OWNER` | UPDATE without owner signature |
| `DEXV_INVALIDATE_NOT_OWNER` | INVALIDATE without owner signature |

### Baseline Errors

| Code | Cause |
|------|-------|
| `DEXV_BASELINE_BUY_TOKEN` | Missing buy token |
| `DEXV_BASELINE_TUPLE` | Token/net mismatch across INs |
| `DEXV_PAIR_NOT_ALLOWED` | Pair not whitelisted |

### Fill Policy Errors

| Code | Cause |
|------|-------|
| `DEXV_MIN_FILL_AON` | AON order partially filled |
| `DEXV_MIN_FILL_NOT_REACHED` | Below min_fill threshold |
| `DEXV_EXPIRED` | Order expired |

### Payout Errors

| Code | Cause |
|------|-------|
| `DEXV_SELLER_PAYOUT_MISMATCH` | Incorrect buy token amount |
| `DEXV_SELLER_PAID_IN_UPDATE` | Seller paid in UPDATE (forbidden) |
| `DEXV_BUY_TOKEN_LEAK` | Buy token not fully distributed |
| `DEXV_SELL_TOKEN_LEAK` | Sell token not fully distributed |
| `DEXV_BUYER_PAYOUT_ADDR_MISMATCH` | Buyer receives to wrong address |

### Fee Errors

| Code | Cause |
|------|-------|
| `DEXV_SERVICE_FEE_UNDERPAID` | Below required service fee |
| `DEXV_SERVICE_FEE_ADDR_BLANK` | Service wallet not configured |
| `DEXV_NETWORK_FEE_UNDERPAID` | Below required network fee |
| `DEXV_FEE_NOT_FROM_BUYER` | Fee paid by wrong party |
| `DEXV_INVALID_FEE_CONFIG` | Malformed fee_config byte |

### Constraint Errors

| Code | Cause |
|------|-------|
| `DEXV_SELF_PURCHASE` | Buyer equals seller |
| `DEXV_MULTI_BUYER_DEST` | Multiple buyer addresses |
| `DEXV_IMMUTABLES_VIOLATION` | Changed immutable fields |
| `DEXV_ROOT_CHAIN_MISMATCH` | order_root doesn't match chain |
| `DEXV_LEFTOVER_STRUCTURE_VIOLATION` | Invalid leftover position |

---

## Immutable Fields

These fields cannot change across order chain:

| Field | Description |
|-------|-------------|
| `seller_addr` | Order owner address |
| `buy_net_id` | Buy token network |
| `sell_net_id` | Sell token network |
| `buy_token` | Buy token ticker |

```c
dap_do_if_any(RET_ERR(DEXV_IMMUTABLES_VIOLATION),
    !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, 
                            &l_prev->subtype.srv_dex.seller_addr),
    l_out_cond->subtype.srv_dex.buy_net_id.uint64 != l_prev->subtype.srv_dex.buy_net_id.uint64,
    ...);
```

---

## Min Fill Validation

### Current Value Mode (bit7=0)

```c
uint256_t l_min_abs = s_calc_pct(l_prev->header.value, l_pct);
if (compare256(l_executed, l_min_abs) < 0)
    RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
```

### Original Value Mode (bit7=1)

```c
// Fetch original order value from root TX
s_dex_fetch_min_abs(a_ledger, &l_root_hash, &l_min_abs);
if (compare256(l_executed, l_min_abs) < 0)
    RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
```

### AON (100%)

```c
if (l_pct == 100 && compare256(l_executed, l_prev->header.value) != 0)
    RET_ERR(DEXV_MIN_FILL_AON);
```

---

## Seller Leftover vs Buyer Leftover

### Detection

```c
bool l_is_seller_leftover = 
    dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, 
                           &l_prev->subtype.srv_dex.seller_addr);
```

### Seller Leftover Rules

- Must be first IN_COND
- `order_root_hash` must match chain
- Same seller address as consumed order

### Buyer Leftover Rules

- Different seller address than any consumed order
- Starts new order chain
- Side inverted from consumed orders

---

## Self-Purchase Prevention

```c
if (dap_chain_addr_compare(&l_buyer_addr, &l_seller_addr))
    RET_ERR(DEXV_SELF_PURCHASE);
```

Verified at:
- Match building (composer)
- Verification (ledger)

---

## Expiry Check

```c
if (l_prev->header.ts_expires && l_now > l_prev->header.ts_expires)
    RET_ERR(DEXV_EXPIRED);
```

Skipped for:
- UPDATE (owner can update expired orders)
- INVALIDATE (owner can cancel expired orders)

---

## Fee Aggregation Verification

Service fee can be combined with seller payout:

```c
// If seller == service wallet
if (dap_chain_addr_compare(&l_seller_addr, &l_srv_addr)) {
    // Fee is included in payout, not separate OUT
    l_expected_total = l_seller_payout + l_service_fee;
}
```

---

## Registration

```c
dap_ledger_verificator_add(
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX,
    s_dex_verificator_callback,
    NULL
);
```

Called during `dap_chain_net_srv_dex_init()`.


