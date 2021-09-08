#include "dap_core.h"
#include "dap_crypto.h"

#define LOG_TAG "main.c"

int main(int argc, char **argv){
    dap_set_appname("example-0");
    g_sys_dir_path = dap_strdup_printf("%s-log", argv[0]);
    printf("%s\n", g_sys_dir_path);
    dap_mkdir_with_parents(g_sys_dir_path);
    char *log_file = dap_strdup_printf("%s/%s.log", g_sys_dir_path, dap_get_appname());
    printf("%s\n", log_file);
    if(dap_common_init(dap_get_appname(), log_file, dap_get_appname()) != 0){
        printf("Can't init common from dap_core module");
        return -2;
    }
    dap_enc_init();
    dap_enc_key_init();
    log_it(L_NOTICE, "Start example-0");
    char *test_str = "This is test string";
    size_t size_in_data = dap_strlen(test_str);
    size_t size_out_data = DAP_ENC_BASE58_ENCODE_SIZE(size_in_data);
    void *enc_data = DAP_NEW_SIZE(void, size_out_data);
    char out_data[size_in_data];
    dap_enc_base58_encode(test_str, size_in_data, enc_data);
    dap_enc_base58_decode(enc_data, &out_data);

    if (dap_strcmp(test_str, out_data) == 0){
        log_it(L_NOTICE, "Encode and decode === ok!\n");
    } else {
        log_it(L_ERROR, "Encode and decode === FAIL!\n");
    }
    log_it(L_MSG, "in_str: %s\nencode_str: %s\nencode_size: %zu\ndecode_str: %s\n size_decode: %zu", test_str,
           enc_data,
           size_in_data,
           out_data);
    scanf("Enter any key:");
    return 0;
}
