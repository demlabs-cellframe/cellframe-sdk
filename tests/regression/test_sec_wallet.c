/**
 * @file test_sec_wallet.c
 * @brief Regression: wallet file hygiene (Oct-2026 security review)
 *
 * Covers the wallet hardening:
 *  - encrypted wallets are written in format v3 (salt + iterated KDF) and
 *    load back with the right password only;
 *  - wallet files are created 0600 (they carry the private key; the old
 *    mode was 0644);
 *  - an empty password is rejected instead of producing a wallet encrypted
 *    with a publicly known constant key;
 *  - the no-password (v1, plaintext) path still works.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dap_common.h"
#include "dap_test.h"
#include "dap_file_utils.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"

#define LOG_TAG "sec_wallet"

static int s_failures = 0;

#define SEC_ASSERT(cond, name) { \
    if (cond) { dap_pass_msg(name); } \
    else { s_failures++; dap_fail(name); } \
}

static const char *s_wallets_dir = "test_wallets_sec";

static uint32_t read_wallet_version(const char *a_file)
{
    FILE *f = fopen(a_file, "rb");
    if (!f)
        return 0;
    dap_chain_wallet_file_hdr_t l_hdr = {0};
    size_t l_n = fread(&l_hdr, 1, sizeof(l_hdr), f);
    fclose(f);
    return l_n == sizeof(l_hdr) ? l_hdr.version : 0;
}

static void test_wallet_v3(void)
{
    dap_print_module_name("Security: wallet v3 format, 0600 mode, no empty passwords");
    dap_rm_rf(s_wallets_dir);
    dap_mkdir_with_parents(s_wallets_dir);
    char l_file[1024];
    snprintf(l_file, sizeof(l_file), "%s/secw.dwallet", s_wallets_dir);

    // 1. Encrypted wallet: created, on-disk version 3, mode 0600
    dap_sign_type_t l_sig = { .type = SIG_TYPE_DILITHIUM };
    dap_chain_wallet_t *l_w = dap_chain_wallet_create("secw", s_wallets_dir, l_sig, "s3cret-pass");
    SEC_ASSERT(l_w != NULL, "encrypted wallet created");
    if (!l_w)
        return;
    dap_chain_wallet_close(l_w);

    struct stat l_st = {0};
    SEC_ASSERT(stat(l_file, &l_st) == 0, "wallet file exists");
    SEC_ASSERT((l_st.st_mode & 0777) == 0600, "wallet file mode is 0600");
    SEC_ASSERT(read_wallet_version(l_file) == 3, "on-disk version is 3 (salted KDF)");

    // 2. Reload with the right password
    unsigned int l_stat = 0;
    dap_chain_wallet_t *l_w2 = dap_chain_wallet_open_file(l_file, "s3cret-pass", &l_stat);
    SEC_ASSERT(l_w2 != NULL, "v3 wallet opens with the right password");
    if (l_w2) {
        dap_chain_wallet_internal_t *l_int = (dap_chain_wallet_internal_t *)l_w2->_internal;
        SEC_ASSERT(l_int && l_int->certs_count == 1, "v3 wallet carries its cert");
        dap_chain_wallet_close(l_w2);
    }

    // 3. Wrong password must fail
    l_stat = 0;
    dap_chain_wallet_t *l_w3 = dap_chain_wallet_open_file(l_file, "wrong-pass", &l_stat);
    SEC_ASSERT(l_w3 == NULL, "v3 wallet rejects a wrong password");
    if (l_w3)
        dap_chain_wallet_close(l_w3);

    // 4. Empty password is rejected at creation (used to produce a constant-key "encrypted" wallet)
    dap_chain_wallet_t *l_w4 = dap_chain_wallet_create("secw_empty", s_wallets_dir, l_sig, "");
    SEC_ASSERT(l_w4 == NULL, "empty password wallet creation rejected");
    if (l_w4)
        dap_chain_wallet_close(l_w4);

    // 5. No-password (v1) wallet still works
    dap_chain_wallet_t *l_w5 = dap_chain_wallet_create("secw_plain", s_wallets_dir, l_sig, NULL);
    SEC_ASSERT(l_w5 != NULL, "plaintext v1 wallet created");
    if (l_w5) {
        dap_chain_wallet_close(l_w5);
        char l_file5[1024];
        snprintf(l_file5, sizeof(l_file5), "%s/secw_plain.dwallet", s_wallets_dir);
        SEC_ASSERT(read_wallet_version(l_file5) == 1, "no-password wallet stays version 1");
        unsigned int l_stat6 = 0;
        dap_chain_wallet_t *l_w6 = dap_chain_wallet_open_file(l_file5, NULL, &l_stat6);
        SEC_ASSERT(l_w6 != NULL, "plaintext wallet opens without a password");
        if (l_w6)
            dap_chain_wallet_close(l_w6);
    }

    dap_rm_rf(s_wallets_dir);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    test_wallet_v3();
    return s_failures ? -1 : 0;
}
