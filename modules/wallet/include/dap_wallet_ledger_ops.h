/*
 * Authors:
 * AI Refactoring 2026
 * 
 * Copyright: Demlabs
 * License: All rights reserved
 *
 * dap_wallet_ledger_ops.h - Dependency Inversion interface for wallet-ledger interaction
 * 
 * АРХИТЕКТУРНЫЙ ПРИНЦИП: Dependency Inversion Principle (DIP)
 * 
 * Проблема:
 *   wallet → ledger (wallet вызывает ledger функции)
 *   ledger → wallet (ledger использует wallet адреса)
 *   = Циклическая зависимость!
 *
 * Решение:
 *   wallet → wallet_ledger_ops (зависит только от интерфейса)
 *   ledger → wallet_ledger_ops (реализует интерфейс)
 *   wallet-shared - регистрирует реализацию ledger в wallet
 *
 * Преимущества:
 *   - Разрыв циклической зависимости
 *   - wallet становится чистым модулем (PURE: только ключи и подписи)
 *   - ledger не зависит от wallet напрямую
 *   - Возможность mock реализации для тестов
 */

#ifndef DAP_WALLET_LEDGER_OPS_H
#define DAP_WALLET_LEDGER_OPS_H

#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_list.h"
#include "dap_chain_datum_tx.h"  // For dap_chain_datum_tx_t
#include "dap_chain_common.h"     // For dap_chain_tx_used_out_item_t

// Forward declarations
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief Callback для получения баланса адреса
 * @param a_ledger Указатель на ledger
 * @param a_addr Адрес для проверки баланса
 * @param a_token_ticker Тикер токена
 * @return Баланс в datoshi
 */
typedef uint256_t (*dap_wallet_ledger_calc_balance_callback_t)(
    dap_ledger_t *a_ledger,
    const dap_chain_addr_t *a_addr,
    const char *a_token_ticker
);

/**
 * @brief Callback для поиска транзакции по адресу
 * @param a_ledger Указатель на ledger
 * @param a_token_ticker Тикер токена
 * @param a_addr_from Адрес отправителя
 * @param a_hash_from Хеш предыдущей транзакции (для итерации)
 * @return Указатель на транзакцию или NULL
 */
typedef dap_chain_datum_tx_t* (*dap_wallet_ledger_tx_find_by_addr_callback_t)(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker,
    const dap_chain_addr_t *a_addr_from,
    dap_chain_hash_fast_t *a_hash_from
);

/**
 * @brief Callback для получения тикера токена по хешу транзакции
 * @param a_ledger Указатель на ledger
 * @param a_tx_hash Хеш транзакции
 * @return Тикер токена или NULL
 */
typedef const char* (*dap_wallet_ledger_tx_get_token_ticker_callback_t)(
    dap_ledger_t *a_ledger,
    const dap_chain_hash_fast_t *a_tx_hash
);

/**
 * @brief Callback для проверки использован ли out item
 * @param a_ledger Указатель на ledger
 * @param a_tx_hash Хеш транзакции
 * @param a_out_idx Индекс out item
 * @param a_out_cond_idx Индекс условного out (может быть NULL)
 * @return true если использован, false иначе
 */
typedef bool (*dap_wallet_ledger_tx_hash_is_used_out_callback_t)(
    dap_ledger_t *a_ledger,
    const dap_chain_hash_fast_t *a_tx_hash,
    int a_out_idx,
    int *a_out_cond_idx
);

/**
 * @brief Callback для получения списка всех токенов адреса
 * @param a_ledger Указатель на ledger
 * @param a_addr Адрес
 * @param a_tickers Выходной массив тикеров
 * @param a_tickers_size Выходной размер массива
 */
typedef void (*dap_wallet_ledger_addr_get_token_ticker_all_callback_t)(
    dap_ledger_t *a_ledger,
    dap_chain_addr_t *a_addr,
    char ***a_tickers,
    size_t *a_tickers_size
);

/**
 * @brief Callback для получения описания токена
 * @param a_ledger Указатель на ledger
 * @param a_token_ticker Тикер токена
 * @return Описание токена или NULL
 */
typedef const char* (*dap_wallet_ledger_get_description_callback_t)(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker
);

/**
 * @brief Структура операций для взаимодействия wallet с ledger
 * 
 * Эта структура реализует паттерн Strategy + Dependency Inversion.
 * Wallet не зависит от конкретной реализации ledger, а работает через callbacks.
 */
typedef struct dap_wallet_ledger_ops {
    dap_wallet_ledger_calc_balance_callback_t           calc_balance;
    dap_wallet_ledger_tx_find_by_addr_callback_t        tx_find_by_addr;
    dap_wallet_ledger_tx_get_token_ticker_callback_t    tx_get_token_ticker;
    dap_wallet_ledger_tx_hash_is_used_out_callback_t    tx_hash_is_used_out;
    dap_wallet_ledger_addr_get_token_ticker_all_callback_t addr_get_token_ticker_all;
    dap_wallet_ledger_get_description_callback_t        get_description;
} dap_wallet_ledger_ops_t;

/**
 * @brief Регистрирует реализацию ledger операций для wallet
 * 
 * Эта функция должна вызываться модулем wallet-shared при инициализации,
 * чтобы связать wallet с реальной реализацией ledger.
 * 
 * @param a_ops Указатель на структуру с callbacks
 */
void dap_wallet_ledger_ops_register(const dap_wallet_ledger_ops_t *a_ops);

/**
 * @brief Получает текущую реализацию ledger операций
 * @return Указатель на структуру ops или NULL если не зарегистрировано
 */
const dap_wallet_ledger_ops_t* dap_wallet_ledger_ops_get(void);

#endif // DAP_WALLET_LEDGER_OPS_H
