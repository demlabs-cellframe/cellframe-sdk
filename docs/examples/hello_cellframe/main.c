/**
 * @file main.c
 * @brief Простейший пример использования CellFrame SDK
 *
 * Этот пример демонстрирует базовую инициализацию и завершение работы с CellFrame SDK.
 * Он может служить отправной точкой для разработки блокчейн-приложений.
 */

#include "dap_chain.h"
#include "dap_chain_net.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Точка входа в приложение
 *
 * @return 0 при успешном выполнении, -1 при ошибке
 */
int main(int argc, char *argv[]) {
    (void)argc;  // Подавление предупреждения о неиспользуемом параметре
    (void)argv;  // Подавление предупреждения о неиспользуемом параметре

    printf("CellFrame SDK Hello World Example\n");
    printf("==================================\n\n");

    // Инициализация CellFrame SDK
    printf("Initializing CellFrame SDK...\n");
    int init_result = dap_chain_init();
    if (init_result != 0) {
        fprintf(stderr, "ERROR: Failed to initialize CellFrame SDK (code: %d)\n", init_result);
        return EXIT_FAILURE;
    }
    printf("✓ CellFrame SDK initialized successfully\n");

    // Создание тестовой сети
    printf("\nCreating test network...\n");
    dap_chain_net_t *net = dap_chain_net_create("hello_network");
    if (!net) {
        fprintf(stderr, "ERROR: Failed to create network\n");
        dap_chain_deinit();
        return EXIT_FAILURE;
    }
    printf("✓ Network 'hello_network' created successfully\n");
    printf("  Network ID: %u\n", net->id.uint64);

    // Создание цепочки
    printf("\nCreating blockchain...\n");
    dap_chain_t *chain = dap_chain_new("hello_chain");
    if (!chain) {
        fprintf(stderr, "ERROR: Failed to create chain\n");
        dap_chain_net_delete(net);
        dap_chain_deinit();
        return EXIT_FAILURE;
    }
    printf("✓ Chain 'hello_chain' created successfully\n");

    // Вывод информации о цепочке
    printf("\nChain Information:\n");
    printf("  Name: %s\n", chain->name);
    printf("  ID: %llu\n", (unsigned long long)chain->id.uint64);

    // Демонстрация работы со временем
    printf("\nTime Management Example:\n");
    dap_time_t current_time = dap_time_now();
    char time_str[64];
    dap_time_to_string(current_time, time_str, sizeof(time_str));
    printf("  Current time: %s\n", time_str);

    // Создание простого кошелька
    printf("\nWallet Creation Example:\n");
    dap_chain_wallet_t *wallet = dap_chain_wallet_create("demo_wallet", net, DAP_ENC_KEY_TYPE_SIG_DILITHIUM);
    if (wallet) {
        char addr_str[128];
        dap_chain_addr_to_str(&wallet->addr, addr_str, sizeof(addr_str));
        printf("✓ Wallet created successfully\n");
        printf("  Wallet address: %s\n", addr_str);

        // Освобождение кошелька
        dap_chain_wallet_delete(wallet);
        printf("✓ Wallet resources freed\n");
    } else {
        printf("✗ Failed to create wallet\n");
    }

    // Очистка ресурсов
    printf("\nCleaning up resources...\n");
    dap_chain_free(chain);
    printf("✓ Chain resources freed\n");

    dap_chain_net_delete(net);
    printf("✓ Network resources freed\n");

    dap_chain_deinit();
    printf("✓ CellFrame SDK shut down successfully\n");

    printf("\n==================================\n");
    printf("Example completed successfully!\n");
    printf("You can now explore more advanced CellFrame SDK features:\n");
    printf("  - Wallet operations\n");
    printf("  - Transaction creation\n");
    printf("  - Consensus algorithms\n");
    printf("  - Network communication\n");

    return EXIT_SUCCESS;
}
