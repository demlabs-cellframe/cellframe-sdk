/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_list.h"

/**
 * @file dap_chain_tx_compose_api.h
 * @brief TX Compose Plugin System API
 * 
 * ARCHITECTURE: Dependency Inversion via Registration
 * 
 * ПРИНЦИПЫ:
 * - Модули регистрируют свои TX builders, а не вызываются напрямую
 * - API не зависит от конкретных реализаций (Zero Coupling)
 * - Любой модуль может зарегистрировать новый тип TX
 * - Plugin система для расширения без изменения ядра
 * 
 * ИСПОЛЬЗОВАНИЕ:
 * 
 * 1. Модуль регистрирует свой TX builder:
 *    ```c
 *    // В wallet_init():
 *    dap_chain_tx_compose_register("transfer", wallet_transfer_builder, NULL);
 *    ```
 * 
 * 2. Вызывающий код создаёт TX через API:
 *    ```c
 *    // Найти UTXO
 *    dap_list_t *l_utxo = dap_ledger_get_utxo_for_value(...);
 *    
 *    // Подготовить параметры
 *    transfer_params_t l_params = { ... };
 *    
 *    // Создать TX через dispatcher
 *    dap_chain_datum_t *l_datum = dap_chain_tx_compose_create(
 *        "transfer", l_ledger, l_utxo, &l_params
 *    );
 *    ```
 * 
 * ПОДДЕРЖИВАЕМЫЕ ТИПЫ TX:
 * - "transfer" - базовый перевод (wallet module)
 * - "multi_transfer" - множественный перевод (wallet module)
 * - "cond_output" - условный output для сервисов (net/srv module)
 * - "event" - ledger event (ledger module)
 * - "from_emission" - TX из эмиссии (ledger module)
 * - Любые кастомные типы, зарегистрированные модулями/сервисами
 */

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief TX Compose callback signature
 * 
 * Модуль реализует эту функцию для создания TX своего типа
 * 
 * @param a_ledger Ledger context для подписи и операций
 * @param a_list_used_outs Список предварительно найденных UTXO (dap_chain_tx_used_out_t*)
 * @param a_params Параметры для данного типа TX (тип зависит от TX type)
 * @return Готовый подписанный datum или NULL при ошибке
 * 
 * ПРИМЕЧАНИЕ: Callback должен:
 * 1. Построить unsigned TX из UTXO
 * 2. Подписать TX через dap_ledger_sign_data()
 * 3. Конвертировать в datum
 * 4. Вернуть готовый datum
 */
typedef dap_chain_datum_t* (*dap_chain_tx_compose_callback_t)(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
);

/**
 * @brief Регистрация TX builder для конкретного типа
 * 
 * Вызывается модулем при инициализации для регистрации своего builder'а
 * 
 * @param a_tx_type Строковый идентификатор типа TX (например, "transfer", "stake", "voting")
 * @param a_callback Функция для создания TX данного типа
 * @param a_user_data Пользовательские данные (опционально, может быть NULL)
 * @return 0 при успехе, отрицательное значение при ошибке
 * 
 * ПРИМЕРЫ:
 * ```c
 * // Wallet module регистрирует базовые операции:
 * dap_chain_tx_compose_register("transfer", wallet_create_transfer_cb, NULL);
 * dap_chain_tx_compose_register("multi_transfer", wallet_create_multi_transfer_cb, NULL);
 * 
 * // Ledger module регистрирует системные операции:
 * dap_chain_tx_compose_register("event", ledger_create_event_cb, NULL);
 * dap_chain_tx_compose_register("from_emission", ledger_create_emission_cb, NULL);
 * 
 * // Service регистрирует свою операцию:
 * dap_chain_tx_compose_register("srv_stake", stake_create_tx_cb, srv_context);
 * ```
 */
int dap_chain_tx_compose_register(
    const char *a_tx_type,
    dap_chain_tx_compose_callback_t a_callback,
    void *a_user_data
);

/**
 * @brief Отмена регистрации TX builder
 * 
 * Вызывается модулем при деинициализации
 * 
 * @param a_tx_type Строковый идентификатор типа TX
 */
void dap_chain_tx_compose_unregister(const char *a_tx_type);

/**
 * @brief Создание TX через зарегистрированный builder (dispatcher)
 * 
 * Главная функция API - диспетчеризирует вызов на конкретный builder
 * 
 * @param a_tx_type Тип TX для создания (например, "transfer")
 * @param a_ledger Ledger context
 * @param a_list_used_outs Список UTXO для входов TX
 * @param a_params Параметры для конкретного типа TX (структура зависит от типа)
 * @return Готовый подписанный datum или NULL при ошибке
 * 
 * ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:
 * 
 * ```c
 * // Transfer TX:
 * typedef struct {
 *     dap_chain_addr_t *addr_to;
 *     const char *ticker;
 *     uint256_t value;
 *     uint256_t fee;
 *     const char *wallet_name;  // Для подписи
 * } transfer_params_t;
 * 
 * transfer_params_t params = {
 *     .addr_to = &l_addr_to,
 *     .ticker = "CELL",
 *     .value = l_value,
 *     .fee = l_fee,
 *     .wallet_name = "my_wallet"
 * };
 * 
 * dap_chain_datum_t *datum = dap_chain_tx_compose_create(
 *     "transfer", l_ledger, l_utxo_list, &params
 * );
 * ```
 */
dap_chain_datum_t* dap_chain_tx_compose_create(
    const char *a_tx_type,
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
);

/**
 * @brief Проверка, зарегистрирован ли builder для данного типа
 * 
 * @param a_tx_type Тип TX для проверки
 * @return true если builder зарегистрирован, false иначе
 */
bool dap_chain_tx_compose_is_registered(const char *a_tx_type);

/**
 * @brief Инициализация TX Compose API
 * 
 * Вызывается автоматически при инициализации datum модуля
 * 
 * @return 0 при успехе, отрицательное значение при ошибке
 */
int dap_chain_tx_compose_init(void);

/**
 * @brief Деинициализация TX Compose API
 * 
 * Вызывается автоматически при деинициализации datum модуля
 */
void dap_chain_tx_compose_deinit(void);

#ifdef __cplusplus
}
#endif

