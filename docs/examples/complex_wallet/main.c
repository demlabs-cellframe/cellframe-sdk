/*
 * CellFrame SDK Complex Wallet Example
 *
 * This example demonstrates advanced usage of CellFrame SDK with:
 * - Wallet management and key operations
 * - Transaction composition and signing
 * - Network interaction and RPC calls
 * - Error handling and logging
 * - Multi-threading support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

// CellFrame SDK headers
#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net.h"
#include "dap_chain_mempool.h"
#include "dap_chain_tx_compose.h"
#include "dap_enc_key.h"
#include "dap_cert.h"

#define CONFIG_FILE "complex_wallet.conf"
#define WALLET_CERT_FILE "wallet_cert.pem"
#define WALLET_KEY_FILE "wallet_key.pem"

// Global variables
volatile sig_atomic_t g_shutdown_requested = 0;
static dap_chain_wallet_t *g_wallet = NULL;
static compose_config_t *g_compose_config = NULL;

// Signal handler
void signal_handler(int signum) {
    g_shutdown_requested = 1;
    printf("\n🛑 Shutdown signal received...\n");
}

/**
 * @brief Initialize the wallet application
 * @param net_name Network name
 * @return 0 on success, -1 on error
 */
int wallet_init(const char *net_name) {
    printf("🚀 Initializing Complex Wallet for network: %s\n", net_name);

    // Initialize DAP SDK
    if (dap_common_init("complex_wallet") != 0) {
        fprintf(stderr, "❌ Failed to initialize DAP SDK\n");
        return -1;
    }

    // Load configuration
    if (dap_config_init(CONFIG_FILE) != 0) {
        printf("⚠️  Configuration file not found, using defaults\n");
    }

    // Initialize network
    if (dap_chain_net_init() != 0) {
        fprintf(stderr, "❌ Failed to initialize network module\n");
        return -1;
    }

    // Initialize wallet module
    if (dap_chain_wallet_init() != 0) {
        fprintf(stderr, "❌ Failed to initialize wallet module\n");
        return -1;
    }

    // Initialize mempool
    if (dap_chain_mempool_init() != 0) {
        fprintf(stderr, "❌ Failed to initialize mempool\n");
        return -1;
    }

    // Create compose configuration
    g_compose_config = calloc(1, sizeof(compose_config_t));
    if (!g_compose_config) {
        fprintf(stderr, "❌ Failed to allocate compose config\n");
        return -1;
    }

    g_compose_config->net_name = strdup(net_name);
    g_compose_config->url_str = strdup("http://rpc.cellframe.net");
    g_compose_config->cert_path = NULL;
    g_compose_config->port = 8081;
    g_compose_config->enc = false;

    printf("✅ Complex Wallet initialized successfully\n");
    return 0;
}

/**
 * @brief Create or load wallet
 * @param wallet_name Wallet name
 * @return 0 on success, -1 on error
 */
int wallet_create(const char *wallet_name) {
    printf("🔑 Creating wallet: %s\n", wallet_name);

    // Create new encryption key
    dap_enc_key_t *key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_ECDSA);
    if (!key) {
        fprintf(stderr, "❌ Failed to create encryption key\n");
        return -1;
    }

    // Generate key pair
    if (dap_enc_key_generate(key) != 0) {
        fprintf(stderr, "❌ Failed to generate key pair\n");
        dap_enc_key_delete(key);
        return -1;
    }

    // Create wallet
    g_wallet = dap_chain_wallet_create(wallet_name, key);
    if (!g_wallet) {
        fprintf(stderr, "❌ Failed to create wallet\n");
        dap_enc_key_delete(key);
        return -1;
    }

    // Save wallet certificate
    if (dap_chain_wallet_save_cert(g_wallet, WALLET_CERT_FILE) != 0) {
        fprintf(stderr, "⚠️  Failed to save wallet certificate\n");
    }

    printf("✅ Wallet created successfully\n");
    printf("📄 Wallet address: %s\n", dap_chain_wallet_get_address(g_wallet));

    return 0;
}

/**
 * @brief Load existing wallet
 * @param wallet_name Wallet name
 * @return 0 on success, -1 on error
 */
int wallet_load(const char *wallet_name) {
    printf("📂 Loading wallet: %s\n", wallet_name);

    // Load wallet from certificate
    g_wallet = dap_chain_wallet_load_from_cert(wallet_name, WALLET_CERT_FILE);
    if (!g_wallet) {
        fprintf(stderr, "❌ Failed to load wallet from certificate\n");
        return -1;
    }

    printf("✅ Wallet loaded successfully\n");
    printf("📄 Wallet address: %s\n", dap_chain_wallet_get_address(g_wallet));

    return 0;
}

/**
 * @brief Get wallet balance
 * @return 0 on success, -1 on error
 */
int wallet_get_balance() {
    if (!g_wallet || !g_compose_config) {
        fprintf(stderr, "❌ Wallet not initialized\n");
        return -1;
    }

    printf("📊 Getting wallet balance...\n");

    // Get network info
    dap_chain_net_id_t net_id = dap_get_net_id(g_compose_config->net_name);
    if (net_id.uint64 == 0) {
        fprintf(stderr, "❌ Invalid network name\n");
        return -1;
    }

    // Get wallet address
    dap_chain_addr_t *wallet_addr = dap_chain_wallet_get_addr(g_wallet);
    if (!wallet_addr) {
        fprintf(stderr, "❌ Failed to get wallet address\n");
        return -1;
    }

    // Get balance via RPC
    uint256_t balance = {0};
    if (!dap_get_remote_wallet_balance(wallet_addr, "CELL", &balance, g_compose_config)) {
        fprintf(stderr, "❌ Failed to get wallet balance\n");
        DAP_FREE(wallet_addr);
        return -1;
    }

    char balance_str[100];
    dap_chain_balance_to_char(&balance, balance_str, sizeof(balance_str));
    printf("💰 Wallet balance: %s CELL\n", balance_str);

    DAP_FREE(wallet_addr);
    return 0;
}

/**
 * @brief Create and send transaction
 * @param recipient_address Recipient address
 * @param amount Amount to send
 * @param token_ticker Token ticker
 * @return 0 on success, -1 on error
 */
int wallet_send_transaction(const char *recipient_address, const char *amount, const char *token_ticker) {
    if (!g_wallet || !g_compose_config) {
        fprintf(stderr, "❌ Wallet not initialized\n");
        return -1;
    }

    printf("💸 Creating transaction...\n");
    printf("📤 To: %s\n", recipient_address);
    printf("💰 Amount: %s %s\n", amount, token_ticker);

    // Parse recipient address
    dap_chain_addr_t *addr_to = dap_chain_addr_from_str(recipient_address);
    if (!addr_to) {
        fprintf(stderr, "❌ Invalid recipient address\n");
        return -1;
    }

    // Parse amount
    uint256_t value_send = dap_chain_balance_scan(amount);
    if (uint256_is_zero(value_send)) {
        fprintf(stderr, "❌ Invalid amount\n");
        DAP_FREE(addr_to);
        return -1;
    }

    // Create transaction
    json_object *tx_json = dap_tx_create_compose(
        g_compose_config->net_name,
        token_ticker,
        amount,
        "0.001",  // fee
        recipient_address,
        dap_chain_wallet_get_addr(g_wallet),
        g_compose_config->url_str,
        g_compose_config->port,
        NULL  // no encryption cert
    );

    if (!tx_json) {
        fprintf(stderr, "❌ Failed to create transaction\n");
        DAP_FREE(addr_to);
        return -1;
    }

    printf("✅ Transaction created successfully\n");

    // Send transaction via RPC
    json_object *response = dap_request_command_to_rpc(tx_json, g_compose_config);
    if (!response) {
        fprintf(stderr, "❌ Failed to send transaction\n");
        json_object_put(tx_json);
        DAP_FREE(addr_to);
        return -1;
    }

    printf("✅ Transaction sent successfully\n");

    // Cleanup
    json_object_put(response);
    json_object_put(tx_json);
    DAP_FREE(addr_to);

    return 0;
}

/**
 * @brief Get transaction history
 * @return 0 on success, -1 on error
 */
int wallet_get_history() {
    if (!g_wallet || !g_compose_config) {
        fprintf(stderr, "❌ Wallet not initialized\n");
        return -1;
    }

    printf("📋 Getting transaction history...\n");

    // Get wallet address
    dap_chain_addr_t *wallet_addr = dap_chain_wallet_get_addr(g_wallet);
    if (!wallet_addr) {
        fprintf(stderr, "❌ Failed to get wallet address\n");
        return -1;
    }

    // Get transaction history via RPC
    json_object *history = dap_request_command_to_rpc_with_params(
        g_compose_config,
        "get_history",
        "addr=%s&limit=10",
        dap_chain_addr_to_str(wallet_addr)
    );

    if (!history) {
        fprintf(stderr, "❌ Failed to get transaction history\n");
        DAP_FREE(wallet_addr);
        return -1;
    }

    printf("✅ Transaction history retrieved\n");

    // Parse and display history (simplified)
    printf("📄 Recent transactions:\n");
    // Here you would parse the JSON response and display transactions

    // Cleanup
    json_object_put(history);
    DAP_FREE(wallet_addr);

    return 0;
}

/**
 * @brief Main wallet processing loop
 * @return 0 on success, -1 on error
 */
int wallet_process() {
    // Display wallet menu
    printf("\n=== Complex Wallet Menu ===\n");
    printf("1. Get Balance\n");
    printf("2. Send Transaction\n");
    printf("3. Get Transaction History\n");
    printf("4. Exit\n");
    printf("Choose option: ");

    char choice[10];
    if (!fgets(choice, sizeof(choice), stdin)) {
        return -1;
    }

    int option = atoi(choice);

    switch (option) {
        case 1:
            return wallet_get_balance();
        case 2: {
            char recipient[100], amount[50], token[20];

            printf("Enter recipient address: ");
            if (!fgets(recipient, sizeof(recipient), stdin)) return -1;
            recipient[strcspn(recipient, "\n")] = 0;

            printf("Enter amount: ");
            if (!fgets(amount, sizeof(amount), stdin)) return -1;
            amount[strcspn(amount, "\n")] = 0;

            printf("Enter token ticker (default: CELL): ");
            if (!fgets(token, sizeof(token), stdin)) return -1;
            token[strcspn(token, "\n")] = 0;
            if (strlen(token) == 0) strcpy(token, "CELL");

            return wallet_send_transaction(recipient, amount, token);
        }
        case 3:
            return wallet_get_history();
        case 4:
            g_shutdown_requested = 1;
            return 0;
        default:
            printf("❌ Invalid option\n");
            return 0;
    }
}

/**
 * @brief Cleanup wallet resources
 */
void wallet_cleanup() {
    printf("🛑 Cleaning up wallet resources...\n");

    if (g_wallet) {
        dap_chain_wallet_close(g_wallet);
        g_wallet = NULL;
    }

    if (g_compose_config) {
        if (g_compose_config->net_name) free((void*)g_compose_config->net_name);
        if (g_compose_config->url_str) free((void*)g_compose_config->url_str);
        if (g_compose_config->cert_path) free((void*)g_compose_config->cert_path);
        free(g_compose_config);
        g_compose_config = NULL;
    }

    // Cleanup modules
    dap_chain_mempool_deinit();
    dap_chain_wallet_deinit();
    dap_chain_net_deinit();
    dap_config_deinit();
    dap_common_deinit();

    printf("✅ Wallet cleanup completed\n");
}

/**
 * @brief Main entry point
 */
int main(int argc, char *argv[]) {
    const char *net_name = (argc > 1) ? argv[1] : "Backbone";
    const char *wallet_name = (argc > 2) ? argv[2] : "my_wallet";

    printf("🚀 Starting Complex Wallet Application\n");
    printf("🌐 Network: %s\n", net_name);
    printf("👛 Wallet: %s\n", wallet_name);

    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize wallet
    if (wallet_init(net_name) != 0) {
        fprintf(stderr, "❌ Failed to initialize wallet\n");
        return EXIT_FAILURE;
    }

    // Try to load existing wallet, create new if doesn't exist
    if (wallet_load(wallet_name) != 0) {
        printf("📝 Creating new wallet...\n");
        if (wallet_create(wallet_name) != 0) {
            fprintf(stderr, "❌ Failed to create wallet\n");
            wallet_cleanup();
            return EXIT_FAILURE;
        }
    }

    // Main processing loop
    while (!g_shutdown_requested) {
        if (wallet_process() != 0) {
            fprintf(stderr, "❌ Wallet processing failed\n");
            break;
        }

        // Small delay to prevent CPU hogging
        usleep(100000); // 100ms
    }

    // Cleanup
    wallet_cleanup();
    printf("✅ Complex Wallet finished successfully!\n");

    return EXIT_SUCCESS;
}
