# Анализ циклических зависимостей (после декомпозиции cmd)

## Обнаруженный цикл: wallet ↔ net ↔ ledger ↔ mempool

### Детальный анализ каждой зависимости:

#### 1. ledger → wallet
**Файл**: `modules/ledger/dap_chain_ledger_cli.c`
**Использует**:
- `dap_chain_wallet_cache_tx_find_in_history()`
- `dap_chain_wallet_cache_iter_create()`
- `dap_chain_wallet_cache_iter_get()`

**Анализ**: CLI функционал (tx_history) использует wallet cache.
**Решение**: Это ПРАВИЛЬНАЯ зависимость (CLI высокоуровневый).

#### 2. ledger → mempool  
**Файл**: `modules/ledger/dap_chain_ledger_cli.c`
**Использует**:
- `dap_chain_mempool_tx_create*()`
- `dap_chain_mempool_datum_add()`
- `dap_chain_mempool_group_new()`

**Анализ**: CLI создаёт TX через mempool.
**Решение**: Это ПРАВИЛЬНАЯ зависимость (CLI высокоуровневый).

#### 3. ledger → net
**Файл**: `modules/ledger/dap_chain_ledger_cli.c`
**Использует**: net API для работы с сетями
**Анализ**: CLI работает с сетевыми параметрами
**Решение**: Это ПРАВИЛЬНАЯ зависимость (CLI высокоуровневый).

#### 4. mempool → ledger
**Файл**: `modules/mempool/dap_chain_mempool.c`
**Использует**:
- `dap_ledger_get_final_chain_tx_hash()`
- `dap_ledger_tx_get_token_ticker_by_hash()`
- `dap_ledger_tx_find_by_hash()`

**Анализ**: Mempool валидирует TX через ledger.
**Решение**: Это ПРАВИЛЬНАЯ зависимость (mempool высокоуровневый валидатор).

#### 5. mempool → net
**Файл**: `modules/mempool/dap_chain_mempool.c`
**Использует**:
- `dap_chain_net_by_id()`
- `dap_chain_net_iter_start/next()`
- `dap_chain_net_tx_get_fee()`
- Доступ к `net->pub.*`

**Анализ**: Mempool работает с сетевыми параметрами (fee, native_ticker)
**Решение**: Частично через net/core (lookup), частично прямая зависимость.

#### 6. net → ledger ⚠️ ПРОБЛЕМА!
**Файл**: `modules/net/dap_chain_net.c`
**Использует**:
- `dap_ledger_init()`
- `dap_ledger_create()`
- `dap_ledger_load_end()`

**Анализ**: Net СОЗДАЁТ и УПРАВЛЯЕТ ledger - это владение.
**Решение**: Это ПРАВИЛЬНАЯ зависимость (net - менеджер сетей, создаёт ledger).

#### 7. net → mempool ⚠️ ПРОБЛЕМА!
**Файл**: `modules/net/dap_chain_net.c`
**Использует**:
- `dap_chain_mempool_datum_add()` (в API registry)
- `dap_chain_mempool_group_name()`

**Анализ**: Net регистрирует callback для добавления datum в mempool.
**Решение**: CALLBACK PATTERN (уже частично реализован через API registry).

#### 8. wallet → net
**Используется**: Wallet отправляет TX в сеть
**Решение**: Это ПРАВИЛЬНАЯ зависимость.

## ВЫВОД:

### Правильные зависимости (не трогать):
- CLI модули → любые (wallet, ledger, mempool, net) ✅
- mempool → ledger (валидация) ✅
- mempool → net (параметры сети) ✅
- net → ledger (создание и управление) ✅
- wallet → net (отправка TX) ✅

### ПРОБЛЕМНАЯ зависимость:
**net → mempool** (datum_add callback)

**Текущее состояние**: Используется через API registry (Dependency Inversion).

### Почему CMake видит цикл:
`target_link_libraries` создаёт прямые зависимости:
- mempool links ledger
- mempool links net
- net links ledger
- ledger links wallet
- net links wallet (через mempool)

= ЦИКЛ!

### Решение:
**НЕ добавлять `wallet` в ledger links!**
Wallet cache функции должны быть доступны только через final library link.
