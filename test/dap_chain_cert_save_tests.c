#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "dap_test.h"
#include "dap_enc_key.h"
#include "dap_chain_cert.h"
#include "dap_chain_cert_file.h"

#define CERT_FILE_PATH "cert_file_path.tmp"

static void test_cert_memory_file(dap_enc_key_type_t a_key_type)
{
    uint32_t l_cert_buf_size = 0;
    dap_chain_cert_t *l_cert = dap_chain_cert_generate_mem("name 1", a_key_type);
    dap_assert_PIF(l_cert, "Fail create cert");
    uint8_t * l_cert_buf = dap_chain_cert_save_mem(l_cert, &l_cert_buf_size);
    dap_assert_PIF(l_cert_buf, "Fail save cert to memory");
    dap_chain_cert_delete(l_cert);

    dap_chain_cert_t *l_cert2 = dap_chain_cert_mem_load(l_cert_buf, l_cert_buf_size);
    dap_assert_PIF(l_cert2, "Fail read cert from memory");

    dap_chain_cert_delete(l_cert2);
    DAP_DELETE(l_cert_buf);

    dap_pass_msg("Save and load cert in memory successfully");

    dap_chain_cert_t *l_certf = dap_chain_cert_generate_mem("name 2", a_key_type);
    int l_res = dap_chain_cert_save_file(l_certf, CERT_FILE_PATH);
    dap_assert_PIF(!l_res, "Fail save cert to file");
    dap_chain_cert_delete(l_certf);

    dap_chain_cert_t *l_certf2 = dap_chain_cert_file_load(CERT_FILE_PATH);
    dap_assert_PIF(l_certf2, "Fail load cert from file");
    dap_chain_cert_delete(l_certf2);
    // delete temp file
    unlink(CERT_FILE_PATH);

    dap_pass_msg("Save and load cert in file successfully");

}

void init_test_case()
{
    dap_enc_key_init();
}

void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_chain_cert_save_tests_run(void)
{
    dap_print_module_name("dap_chain_cert_save");
    init_test_case();

    test_cert_memory_file(DAP_ENC_KEY_TYPE_SIG_BLISS);
    test_cert_memory_file(DAP_ENC_KEY_TYPE_SIG_TESLA);
    test_cert_memory_file(DAP_ENC_KEY_TYPE_SIG_PICNIC);

    cleanup_test_case();
}
