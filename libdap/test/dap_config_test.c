#include "dap_config_test.h"

static const char * testconfigName = "test_dap_config.cfg";
static const char * config_data = "[db_options]\n"
                                  "db_type=mongoDb\n"
                                  "[server_options]\n"
                                  "timeout=1,0\n"
                                  "vpn_enable=true\n"
                                  "proxy_enable=false\n"
                                  "TTL_session_key=600\n"
                                  "str_arr=[vasya, petya, grisha, petushok@microsoft.com]\n"
                                  "int_arr=[1, 3, 5]\n";

static const size_t STR_ARR_LEN = 4;
static const char * str_add_test_case[] = {
    "vasya",
    "petya",
    "grisha",
    "petushok@microsoft.com"
};
static const size_t INT_ARR_LEN = 3;
static const int32_t int_arr_test_cases[] = {1, 3, 5};


static FILE * config_file;
static dap_config_t * config;

void create_test_config_file() {
    config_file = fopen(testconfigName, "w+");
    dap_assert(config_file != NULL, "Create config file");

    fwrite(config_data, sizeof(char),
           strlen(config_data), config_file);

    fclose(config_file);
}

void init_test_case() {
    create_test_config_file();

    // init dir path for configs files
    dap_config_init(".");

    config = dap_config_open("test_dap_config");
}

void cleanup_test_case() {
    dap_assert(remove("test_dap_config.cfg") == 0,
           "Remove config file");
    dap_config_close(config);
    dap_config_deinit();
}

void test_config_open_fail() {
    dap_assert(dap_config_open("RandomNeverExistName") == NULL,
           "Try open not exists config file");
}

void test_get_int() {
    int32_t resultTTL = dap_config_get_item_int32(config,
                                                  "server_options",
                                                  "TTL_session_key");
    dap_assert(resultTTL == 600, "Get int from config");

}

void test_get_int_default()
{
    int32_t resultTTLDefault = dap_config_get_item_int32_default(config,
                                                                 "server_options",
                                                                 "TTL_session_key",
                                                                 650);
    dap_assert(resultTTLDefault == 600, "The correct valid int value is obtained from the default function");

    int32_t resultTTLDefault1 = dap_config_get_item_int32_default(config,
                                                                 "server_options",
                                                                 "TTL_session_key2",
                                                                 650);
    dap_assert(resultTTLDefault1 == 650, "The correct default value of int from the default function is obtained");
}

void test_get_double() {
    double timeout = dap_config_get_item_double(config,
                                                "server_options",
                                                "timeout");
    dap_assert(timeout == 1.0, "Get double from config");
}

void test_get_double_default()
{
    double timeoutDefault = dap_config_get_item_double_default(config,
                                                                "server_options",
                                                                "timeout",
                                                                1.0);
    dap_assert(timeoutDefault == 1.0, "The correct valid double value is obtained from the default function");

    double timeoutDefault2 = dap_config_get_item_double_default(config,
                                                                "server_options",
                                                                "ghsdgfyhj",
                                                                1.5);
    dap_assert(timeoutDefault2 == 1.5, "The correct default value of double from the default function is obtained");
}

void test_get_bool() {
    bool rBool = dap_config_get_item_bool(config, "server_options", "vpn_enable");
    dap_assert(rBool == true, "Get bool from config");
    rBool = dap_config_get_item_bool(config, "server_options", "proxy_enable");
    dap_assert(rBool == false, "Get bool from config");
}

void test_get_bool_default()
{
    bool rBool = dap_config_get_item_bool_default(config, "server_options", "proxy_enable", true);
    dap_assert(rBool == false, "received true true bool value from a function default");
    rBool = dap_config_get_item_bool_default(config, "server_options", "proxy_enable2", false);
    dap_assert(rBool == false, "the correct default value of bool is obtained from the default function");
}

void test_array_str()
{
    uint16_t arraySize;
    char ** result_arr = dap_config_get_array_str(config, "server_options", "str_arr", &arraySize);

    dap_assert(result_arr != NULL, "Get array str from config");
    dap_assert(arraySize == STR_ARR_LEN, "Check array length");

    for(uint32_t i = 0; i < arraySize; i++) {
        assert(strcmp(result_arr[i], str_add_test_case[i]) == 0 && "test_array_str failed");
    }
}

void test_array_int() {
    uint16_t arraySize;
    char ** result_arr = dap_config_get_array_str(config, "server_options", "int_arr", &arraySize);

    dap_assert(result_arr != NULL, "Get array int");
    dap_assert(arraySize == INT_ARR_LEN, "Check array int length");

    dap_test_msg("Testing array int values.");
    for(uint32_t i = 0; i < arraySize; i++) {
        dap_assert_PIF(atoi(result_arr[i]) == int_arr_test_cases[i], "Check array int");
    }
}

void test_get_item_str()
{
    const char* dct = dap_config_get_item_str(config, "db_options", "db_type");
    const char* E1 = "mongoDb";
    dap_assert(memcmp(dct,E1,7) == 0, "The function returns const char*");
}

void test_get_item_str_default()
{
    const char* E1 = "mongoDb";
    const char* E2 = "EDb";

    const char* dct2 = dap_config_get_item_str_default(config, "db_options", "db_type", "EDb");
    dap_assert(memcmp(dct2,E1,7) == 0, "The function returns the true value of const char *");

    const char* dct3 = dap_config_get_item_str_default(config, "db_options", "db_type2", "EDb");
    dap_assert(memcmp(dct3,E2,3) == 0, "The function returns the default const char *");
}


void dap_config_tests_run()
{
    dap_print_module_name("dap_config");

    init_test_case();

    test_config_open_fail();
    test_get_int();
    test_get_int_default();
    test_get_bool();
    test_get_bool_default();
    test_array_str();
    test_array_int();
    test_get_item_str();
    test_get_item_str_default();
    test_get_double();
    test_get_double_default();

    cleanup_test_case();
}
