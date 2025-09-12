/**
 * @file main.c
 * @brief Простой кошелек CellFrame SDK
 *
 * Этот пример демонстрирует создание и использование кошелька в CellFrame SDK.
 * Он может служить основой для разработки более сложных приложений.
 */

#include "dap_common.h"
#include "dap_chain_wallet.h"
#include "dap_enc_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Точка входа в приложение
 *
 * @return 0 при успешном выполнении, EXIT_FAILURE при ошибке
 */
int main(int argc, char *argv[]) {
    (void)argc;  // Подавление предупреждения о неиспользуемом параметре
    (void)argv;  // Подавление предупреждения о неиспользуемом параметре

    printf("CellFrame SDK Simple Wallet Example\n");
    printf("===================================\n\n");

    // Инициализация DAP SDK
    printf("Initializing DAP SDK...\n");
    int init_result = dap_common_init("simple_wallet", NULL);
    if (init_result != 0) {
        fprintf(stderr, "ERROR: Failed to initialize DAP SDK (code: %d)\n", init_result);
        return EXIT_FAILURE;
    }
    printf("✓ DAP SDK initialized successfully\n");

    // Инициализация wallet модуля
    printf("\nInitializing wallet module...\n");
    if (dap_chain_wallet_init() != 0) {
        fprintf(stderr, "ERROR: Failed to initialize wallet module\n");
        dap_common_deinit();
        return EXIT_FAILURE;
    }
    printf("✓ Wallet module initialized successfully\n");

    // Создание нового кошелька
    printf("\nCreating new wallet...\n");

    // Создание ключа для кошелька
    dap_enc_key_t *key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_ECDSA);
    if (!key) {
        fprintf(stderr, "ERROR: Failed to create encryption key\n");
        dap_chain_wallet_deinit();
        dap_common_deinit();
        return EXIT_FAILURE;
    }

    // Генерация ключа
    if (dap_enc_key_generate(key) != 0) {
        fprintf(stderr, "ERROR: Failed to generate key pair\n");
        dap_enc_key_delete(key);
        dap_chain_wallet_deinit();
        dap_common_deinit();
        return EXIT_FAILURE;
    }

    // Создание кошелька
    dap_chain_wallet_t *wallet = dap_chain_wallet_create("my_wallet", ".", DAP_ENC_KEY_TYPE_SIG_ECDSA, NULL);
    if (!wallet) {
        fprintf(stderr, "ERROR: Failed to create wallet\n");
        dap_enc_key_delete(key);
        dap_chain_wallet_deinit();
        dap_common_deinit();
        return EXIT_FAILURE;
    }
    printf("✓ Wallet created successfully\n");

    // Получение адреса кошелька
    printf("\nGetting wallet address...\n");
    dap_chain_addr_t *wallet_addr = dap_chain_wallet_get_addr(wallet, 0);
    if (!wallet_addr) {
        fprintf(stderr, "ERROR: Failed to get wallet address\n");
        dap_chain_wallet_close(wallet);
        dap_enc_key_delete(key);
        dap_chain_wallet_deinit();
        dap_common_deinit();
        return EXIT_FAILURE;
    }

    // Конвертация адреса в строку (для отображения)
    char *addr_str = dap_chain_addr_to_str(wallet_addr);
    if (addr_str) {
        printf("✓ Wallet address: %s\n", addr_str);
        free(addr_str);
    } else {
        printf("✓ Wallet address obtained (string conversion failed)\n");
    }

    // Получение информации о ключе
    printf("\nWallet key information:\n");
    size_t key_count = dap_chain_wallet_get_certs_number(wallet);
    printf("  Key count: %zu\n", key_count);

    if (key_count > 0) {
        dap_enc_key_t *wallet_key = dap_chain_wallet_get_key(wallet, 0);
        if (wallet_key) {
            printf("  Key type: %d\n", wallet_key->type);
            printf("  ✓ Key retrieved successfully\n");
        } else {
            printf("  ✗ Failed to retrieve key\n");
        }
    }

    // Завершение работы
    printf("\nShutting down...\n");

    // Освобождение ресурсов
    DAP_FREE(wallet_addr);
    dap_chain_wallet_close(wallet);
    dap_enc_key_delete(key);

    // Деинициализация модулей
    dap_chain_wallet_deinit();
    dap_common_deinit();

    printf("✓ Shutdown completed successfully\n");
    printf("\nExample completed successfully!\n");
    printf("You can now explore more advanced CellFrame SDK wallet features.\n");

    return EXIT_SUCCESS;
}



