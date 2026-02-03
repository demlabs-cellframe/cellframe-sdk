# DEX v2 Matching Engine

## Overview

The DEX matching engine supports three purchase modes:

1. **Single Order** — Purchase against specific order hash
2. **Multi Order** — Purchase against list of order hashes
3. **Auto Match** — Automatic matching by criteria (best price first)

---

## Match Criteria

```c
typedef struct dex_match_criteria {
    const char *token_sell, *token_buy;
    dap_chain_net_id_t net_id_sell, net_id_buy;
    uint256_t rate_cap;                  // Price limit (BID: rate<=cap, ASK: rate>=cap)
    uint256_t budget;                    // Amount limit
    bool is_budget_buy;                  // Budget in buy token (true) or sell token (false)
    const dap_chain_addr_t *buyer_addr;  // To skip self-purchase
} dex_match_criteria_t;
```

If `rate_cap` is non-zero, orders are filtered by side: BID skips `rate > rate_cap`, ASK skips `rate < rate_cap`.

### Taker Side Determination

Taker's side is derived from token ordering via `s_pair_normalize`:

```c
if (strcmp(a_sell_tok, a_buy_tok) < 0) {
    // sell < buy lexicographically: BASE=sell, QUOTE=buy → ASK
    *a_side = DEX_SIDE_ASK;
} else {
    // sell >= buy: BASE=buy, QUOTE=sell → BID
    *a_side = DEX_SIDE_BID;
}
```

| `token_sell` | `token_buy` | Canonical Pair | Taker Side | Matches Against |
|--------------|-------------|----------------|------------|-----------------|
| KEL | USDT | KEL/USDT | ASK | BID orders |
| USDT | KEL | KEL/USDT | BID | ASK orders |

**Note:** Taker always matches against **opposite** side orders.

### Budget Canonical Translation

```c
// Unified semantics: is_budget_buy=true means budget in token buyer wants to buy
// Formula: budget_in_base = is_budget_buy == (taker_side == BID)
bool l_budget_in_base = a_criteria->is_budget_buy == (l_side == DEX_SIDE_BID);
```

| Taker Side | `is_budget_buy` | Budget Token | `budget_in_base` |
|------------|-----------------|--------------|------------------|
| BID | `false` | QUOTE | `false` |
| BID | `true` | BASE | `true` |
| ASK | `false` | BASE | `true` |
| ASK | `true` | QUOTE | `false` |

---

## CLI Find Matches

```bash
srv_dex find_matches -net <network_name> -order <hash> -addr <wallet_addr>
```

Notes:

- `-order` accepts any hash in legacy or DEX order chain; it is resolved to the latest tail.
- Budget is the remaining **sell-token** value from the order tail.
- `-addr` is passed as `buyer_addr` to skip self-matches.
- Matching is always against the **opposite** side of the order.

---

## Match Table Entry

```c
typedef struct dex_match_table_entry {
    dex_order_match_t match;      // Order snapshot
    dex_pair_key_t *pair_key;     // Canonical pair
    dap_chain_addr_t seller_addr;
    uint8_t side_version;
    uint32_t flags;
    dap_time_t ts_created, ts_expires;
    
    uint256_t exec_sell;  // Executed BASE amount
    uint256_t exec_min;   // Minimum fill amount
    uint256_t exec_quote; // Exact QUOTE for partial fills
    
    UT_hash_handle hh;    // Keyed by match.tail
} dex_match_table_entry_t;
```

---

## Matching Flow

### Step 1: Build Match Table

From criteria or hashes:

```c
dex_match_table_entry_t *s_dex_matches_build_by_criteria(
    dap_chain_net_t *a_net,
    const dex_match_criteria_t *a_criteria,
    uint256_t *a_out_leftover_budget
);

dex_match_table_entry_t *s_dex_matches_build_by_hashes(
    dap_chain_net_t *a_net,
    const dap_hash_fast_t *a_hashes,
    size_t a_count,
    uint256_t a_budget,
    bool a_is_budget_buy,
    const dap_chain_addr_t *a_buyer_addr,
    dap_chain_net_srv_dex_purchase_error_t *a_out_err,
    uint256_t *a_out_leftover_quote
);
```

### Step 2: Sort by Price

```c
// ASK: lowest rate first (best price for buyer)
HASH_SORT(l_entries, s_cmp_match_entries_ask);

// BID: highest rate first (best price for buyer)
HASH_SORT(l_entries, s_cmp_match_entries_bid);
```

### Step 3: Allocate Budget

Iterate sorted entries, compute `exec_sell` for each:

```c
HASH_ITER(hh, l_entries, l_cur, l_tmp) {
    // Check min_fill policy
    // Calculate executable amount
    // Update remaining budget
}
```

### Step 4: Build Transaction

```c
dap_chain_datum_tx_t *s_dex_compose_from_match_table(
    dap_chain_net_t *a_net,
    dap_chain_wallet_t *a_wallet,
    uint256_t a_fee,
    uint256_t a_leftover_budget,
    bool a_is_budget_buy,
    bool a_create_buyer_order_on_leftover,
    uint256_t a_leftover_rate,
    dex_match_table_entry_t *a_matches
);
```

---

## Budget Allocation Algorithm

### Budget Types

| `is_budget_buy` | Budget Token | Description |
|-----------------|--------------|-------------|
| `true` | Buy token | "I want to receive X tokens" |
| `false` | Sell token | "I want to spend X tokens" |

### Canonical Translation

```c
// l_side0 is MAKER's side (from order)
// buyer's side is opposite
bool l_budget_in_base = a_is_budget_buy == (l_side0 == DEX_SIDE_ASK);
```

### Full Fill

When budget exceeds order size:

```c
if (compare256(a_budget, l_available_base) >= 0) {
    l_cur->exec_sell = l_available_base;
    SUBTRACT_256_256(a_budget, l_available_base, &a_budget);
}
```

### Partial Fill

When budget is exhausted mid-order:

```c
if (l_pct != 100 && !l_order_exhausted) {
    l_cur->exec_sell = a_budget;
    
    // Canonical rounding: exec_quote = exec_sell * rate
    MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_cur->exec_quote);
    DIV_256_COIN(l_cur->exec_quote, l_cur->match.rate, &l_cur->exec_sell);
    
    if (l_pct == 0 || compare256(l_cur->exec_sell, l_cur->exec_min) >= 0) {
        a_budget = uint256_0;  // Drained
    }
}
```

---

## Min Fill Enforcement

### At Match Time

```c
uint8_t l_pct = l_cur->match.min_fill & 0x7F;

// Compute min_fill threshold
if (l_from_origin) {
    s_dex_fetch_min_abs(a_ledger, &l_root, &l_cur->exec_min);  // % of original
} else {
    l_cur->exec_min = s_calc_pct(l_cur->match.value, l_pct);   // % of current
}

// For BID, convert to BASE units
if ((l_cur->side_version & 0x1) == DEX_SIDE_BID)
    DIV_256_COIN(l_cur->exec_min, l_cur->match.rate, &l_cur->exec_min);
```

### AON (100%) Handling

```c
if (l_pct == 100 || l_order_exhausted) {
    // Require full fill
    if (compare256(a_budget, l_available_base) < 0) {
        HASH_DEL(l_entries, l_cur);  // Skip this order
    }
}
```

### Exhausted Orders (Dust)

Orders with remaining value below min_fill are treated as AON:

```c
bool l_order_exhausted = (l_pct > 0 && compare256(l_available_base, l_cur->exec_min) < 0);
```

---

## Price Sorting

### ASK Orders (Rate ASC)

```c
static int s_cmp_match_entries_ask(dex_match_table_entry_t *a, dex_match_table_entry_t *b) {
    int rc = compare256_ptr(&a->match.rate, &b->match.rate);
    return rc ? rc
         : a->ts_created < b->ts_created ? -1
         : a->ts_created > b->ts_created ? 1
         : memcmp(&a->match.root, &b->match.root, sizeof(...));
}
```

Buyer wants **lowest** rate (pay less QUOTE per BASE).

### BID Orders (Rate DESC)

```c
static int s_cmp_match_entries_bid(dex_match_table_entry_t *a, dex_match_table_entry_t *b) {
    int rc = compare256_ptr(&b->match.rate, &a->match.rate);  // Reversed
    return rc ? rc : /* FIFO tie-breakers */;
}
```

Buyer wants **highest** rate (receive more QUOTE per BASE).

---

## Self-Purchase Prevention

```c
if (a_buyer_addr && dap_chain_addr_compare(a_buyer_addr, &l_cur->seller_addr)) {
    continue;  // Skip own orders
}
```

Verified at both:
- Match building time (composer)
- Verification time (ledger)

---

## Partial Match Detection

After sorting, the last match with `exec_sell < full_value` is the partial:

```c
HASH_ITER(hh, a_matches, l_cur_match, l_tmp) {
    uint256_t l_full_base;
    if (l_match0->side_version & 0x1)  // BID
        DIV_256_COIN(l_cur_match->match.value, l_cur_match->match.rate, &l_full_base);
    else  // ASK
        l_full_base = l_cur_match->match.value;

    if (compare256(l_full_base, l_cur_match->exec_sell) > 0) {
        l_partial_match = l_cur_match;
    }
}
```

---

## TX Composition Order

1. **IN items** — Collect buyer's UTXO
2. **IN_COND items** — Partial first, then full matches
3. **OUT items** — Buyer receives, sellers receive, fees
4. **OUT_COND** — Seller residual OR buyer leftover (mutually exclusive)
5. **Signature**

### IN_COND Ordering Rationale

Partial match first ensures:
- Residual OUT_COND is created after all payouts
- Deterministic verification order

```c
if (l_partial_match) {
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_partial_match->match.tail, ...);
}
HASH_ITER(hh, a_matches, l_cur_match, l_tmp) {
    if (l_partial_match == l_cur_match) continue;
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_cur_match->match.tail, ...);
}
```

---

## Buyer Leftover Order

Created when budget not exhausted and `a_create_buyer_order_on_leftover` flag is set.

### Requirements

| Parameter | Required | Description |
|-----------|----------|-------------|
| `a_create_buyer_order_on_leftover` | Yes | Enable leftover order creation |
| `a_leftover_rate` | Yes | Rate for the new order (canonical QUOTE/BASE) |

If `a_leftover_rate` is zero when flag is set, TX composition fails.

### Creation Logic

```c
if (!IS_ZERO_256(a_leftover_budget) && a_create_buyer_order_on_leftover) {
    // Calculate leftover sell value
    // Check dust threshold
    // Create OUT_COND with opposite side
}
```

### Side Continuation

Leftover order **continues taker's intent** by creating an order on the opposite side:

| Matched Orders | Taker Action | Leftover Side | Leftover Action |
|----------------|--------------|---------------|-----------------|
| ASK | Buys BASE | **BID** | Sells QUOTE, buys BASE |
| BID | Sells BASE | **ASK** | Sells BASE, buys QUOTE |

```c
if (l_reqs.side == DEX_SIDE_ASK) {
    // Matched ASK → create BID: sell QUOTE, buy BASE
    l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(...,
        l_key0->net_id_quote, l_leftover_sell_value,  // sell QUOTE
        l_key0->net_id_base, l_token_base,            // buy BASE
        ..., a_leftover_min_fill, ...);
} else {
    // Matched BID → create ASK: sell BASE, buy QUOTE
    l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(...,
        l_key0->net_id_base, l_leftover_sell_value,   // sell BASE
        l_key0->net_id_quote, l_token_quote,          // buy QUOTE
        ..., a_leftover_min_fill, ...);
}
```

### Budget Token Translation

Leftover budget may need conversion depending on `is_budget_buy`:

```c
bool l_leftover_in_quote = (l_reqs.side == DEX_SIDE_ASK) != a_is_budget_buy;
```

| Taker Side | `is_budget_buy` | Leftover Token | Conversion |
|------------|-----------------|----------------|------------|
| ASK (buys BASE) | `false` | QUOTE | Direct |
| ASK (buys BASE) | `true` | BASE | `BASE * rate → QUOTE` |
| BID (sells BASE) | `false` | BASE | Direct |
| BID (sells BASE) | `true` | QUOTE | `QUOTE / rate → BASE` |

**Example for KEL/USDT (BASE=KEL, QUOTE=USDT):**

| Command | Matched | Leftover Budget | Leftover Order |
|---------|---------|-----------------|----------------|
| Buy KEL, `-unit sell` | ASK | 30 USDT | BID: sell 30 USDT |
| Buy KEL, `-unit buy` | ASK | 10 KEL | BID: sell `10 * rate` USDT |
| Sell KEL, `-unit sell` | BID | 20 KEL | ASK: sell 20 KEL |
| Sell KEL, `-unit buy` | BID | 50 USDT | ASK: sell `50 / rate` KEL |

### No Matches Scenario

When no orders match criteria but leftover creation is requested:

```c
if (!l_matches) {
    if (!a_create_buyer_order_on_leftover || IS_ZERO_256(a_leftover_rate))
        return DEX_PURCHASE_AUTO_ERROR_NO_MATCHES;
    // Create fresh ORDER with full budget (not EXCHANGE)
    dap_chain_net_srv_dex_create(a_net, a_buy_token, a_sell_token,
                                  l_value_sell, a_leftover_rate, ...);
}
```

This creates a new order using the entire budget at the specified rate.

### Dust Threshold

Leftover orders below dust threshold are silently skipped:

```c
uint256_t l_leftover_thr = s_dex_dust_threshold_calc(...);
if (!IS_ZERO_256(l_leftover_thr) && compare256(l_leftover_sell_amount, l_leftover_thr) <= 0) {
    l_create_buyer_leftover = false;  // Skip, don't collect tokens
}
```

---

## Mutual Exclusivity

**Seller residual** and **buyer leftover** cannot coexist in same TX:

```c
if (!IS_ZERO_256(a_leftover_budget)) {
    if (l_partial_match) {
        log_it(L_ERROR, "Invalid state: buyer leftover and partial match are mutually exclusive!");
        return NULL;
    }
    // Create buyer leftover
} else if (l_partial_match) {
    // Create seller residual (DEX_TX_TYPE_EXCHANGE in OUT_COND, or OUT_EXT refund when residual is below dust threshold)
}
```

**Note:** Seller residual is classified as `DEX_TX_TYPE_EXCHANGE` (not `UPDATE`).
`UPDATE` is only for owner-initiated value modifications.

---

## Public API

### Single Purchase

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
    uint8_t a_leftover_min_fill,
    dap_chain_datum_tx_t **a_tx
);
```

### Multi Purchase

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

### Auto Purchase

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
    uint8_t a_leftover_min_fill,
    dap_chain_datum_tx_t **a_tx,
    dex_match_table_entry_t **a_matches  // Optional: return matches
);
```

---

## Error Codes

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



