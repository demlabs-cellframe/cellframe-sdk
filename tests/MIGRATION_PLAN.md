# План реорганизации тестов Cellframe SDK

## 🎯 Цель
Организовать все тесты по образу dap-sdk в единой директории `cellframe-sdk/tests/`

## 📁 Целевая структура

```
cellframe-sdk/tests/
├── CMakeLists.txt              # Главный файл сборки тестов
├── README.md                   # Документация по тестированию
├── fixtures/                   # Общие фикстуры и хелперы
│   ├── test_helpers.h/c        # Утилиты для всех тестов
│   ├── mock_network.h/c        # Mock сетевых компонентов
│   ├── mock_wallet.h/c         # Mock кошелька
│   └── sample_data.h           # Тестовые данные
├── unit/                       # Unit тесты (изолированные, с моками)
│   ├── chain/
│   │   ├── test_chain_datum.c
│   │   └── test_chain_tx.c
│   ├── ledger/
│   │   ├── test_ledger_tx.c
│   │   └── test_ledger_token.c
│   ├── net/
│   │   └── tx/
│   │       └── test_tx_compose.c  # ← TX compose mock UTXO тест
│   ├── wallet/
│   │   └── test_wallet_operations.c
│   └── consensus/
│       └── test_esbocs.c
├── integration/                # Integration тесты (реальные компоненты)
│   ├── test_ledger_full.c     # ← DAP_LEDGER_TEST
│   ├── test_chain_blocks.c    # ← DAP_CHAIN_BLOCKS_TEST
│   ├── test_xchange.c          # ← DAP_XCHANGE_TEST
│   ├── test_stake_ext.c        # ← DAP_STAKE_EXT_TEST
│   └── test_mempool_flow.c
├── performance/                # Performance тесты
│   └── test_tps.c              # ← Уже создан tests/performance/dap_tps_test.c
└── e2e/                        # End-to-end тесты
    └── test_full_transaction_flow.c
```

## 📋 План переноса (по приоритету)

### ✅ PHASE 1: Создать инфраструктуру (сделано частично)
- [x] Создана `tests/performance/` для TPS
- [ ] Создать `cellframe-sdk/tests/` главную директорию
- [ ] Создать `CMakeLists.txt` с подмодулями
- [ ] Создать `README.md` с документацией
- [ ] Создать `fixtures/` с общими хелперами

### 🔄 PHASE 2: Перенести unit тесты
**Источник:** `modules/*/tests/` разбросаны по модулям

| Откуда | Куда | Тип | Статус |
|--------|------|-----|--------|
| `modules/chain/tests/dap_chain_ledger_tests.c` | `tests/integration/test_ledger_full.c` | Integration | 🔄 В работе |
| `modules/datum/tests/*` | `tests/unit/chain/test_chain_datum.c` | Unit | ⏸️ TODO |
| `modules/ledger/tests/*` | `tests/unit/ledger/test_ledger_*.c` | Unit | ⏸️ TODO |
| `modules/net/tx/tests/` (только что создано) | `tests/unit/net/tx/test_tx_compose.c` | Unit | 🆕 Новый |
| `modules/type/blocks/tests/*` | `tests/unit/chain/test_blocks.c` | Unit | ⏸️ TODO |

### 🔄 PHASE 3: Перенести ifdef тесты → integration
**Эти тесты требуют реальных компонентов, НЕ моки**

| ifdef блок | Куда | Описание |
|------------|------|----------|
| `DAP_LEDGER_TEST` | `tests/integration/test_ledger_full.c` | ✅ Уже перенесён в fixture |
| `DAP_CHAIN_TX_COMPOSE_TEST` | `tests/unit/net/tx/test_tx_compose.c` | 🔄 Mock UTXO - unit тест |
| `DAP_CHAIN_BLOCKS_TEST` | `tests/integration/test_chain_blocks.c` | ⏸️ Блочные операции |
| `DAP_XCHANGE_TEST` | `tests/integration/test_xchange.c` | ⏸️ XChange flow |
| `DAP_STAKE_EXT_TEST` | `tests/integration/test_stake_ext.c` | ⏸️ Stake operations |
| `DAP_TPS_TEST` | `tests/performance/test_tps.c` | ✅ Уже создан |

### 🔄 PHASE 4: Создать недостающие тесты
- [ ] `tests/unit/wallet/` - тесты кошелька
- [ ] `tests/unit/consensus/` - тесты консенсуса
- [ ] `tests/integration/test_mempool_flow.c` - полный flow mempool
- [ ] `tests/e2e/test_full_transaction_flow.c` - полный TX flow

## 🎯 Текущая задача: PHASE 2 - TX Compose

### Что делаем СЕЙЧАС:
1. ✅ Создали `modules/net/tx/tests/dap_chain_tx_compose_test.c` (временно)
2. 🔄 Удаляем `#ifdef DAP_CHAIN_TX_COMPOSE_TEST` из production
3. ⏭️ Переносим в `tests/unit/net/tx/test_tx_compose.c`

## 📝 Примечания

### Unit vs Integration
- **Unit тесты** - изолированные, с моками, быстрые
  - Mock UTXO генерация
  - Mock network компоненты
  - Тестируют одну функцию/модуль
  
- **Integration тесты** - реальные компоненты, медленнее
  - Полная инициализация ledger
  - Реальная сеть (test network)
  - Тестируют взаимодействие модулей

### Мокирование в integration тестах - OK!
Как ты сказал: "какое-то мокирование там может быть и в интеграционных это окей"
- Можно мокировать внешние зависимости (файлы, сеть)
- НЕ мокируем тестируемые компоненты

## 🚀 Следующие шаги

1. **Сейчас**: Закончить перенос DAP_CHAIN_TX_COMPOSE_TEST
2. **Далее**: Найти DAP_CHAIN_BLOCKS_TEST, DAP_XCHANGE_TEST, DAP_STAKE_EXT_TEST
3. **Потом**: Создать главную структуру `cellframe-sdk/tests/`
4. **Завершение**: Перенести все существующие тесты из `modules/*/tests/`
