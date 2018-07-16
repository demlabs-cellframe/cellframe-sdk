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
    assert(config_file != NULL &&
            "Can't create config file");

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
    assert(remove("test_dap_config.cfg") == 0 &&
           "Error remove config file");
    dap_config_close(config);
}

void test_config_open_fail() {
    assert(dap_config_open("RandomNeverExistName") == NULL
           && "configOpenFail failed");
}

void test_get_int() {
    int32_t resultTTL = dap_config_get_item_int32(config,
                                                  "server_options",
                                                  "TTL_session_key");
    assert(resultTTL == 600 && "get_int failed");
}

void test_get_double() {
    double timeout = dap_config_get_item_double(config,
                                                "server_options",
                                                "timeout");
    assert(timeout == 1.0 && "test_get_double failed");
}

void test_get_bool() {
    bool rBool = dap_config_get_item_bool(config, "server_options", "vpn_enable");
    assert(rBool == true && "test_get_bool failed");
    rBool = dap_config_get_item_bool(config, "server_options", "proxy_enable");
    assert(rBool == false && "test_get_bool failed");
}

void test_array_str() {
    uint16_t arraySize;
    char ** result_arr = dap_config_get_array_str(config, "server_options", "str_arr", &arraySize);

    assert(result_arr != NULL && "test_array_str failed, result_arr is NULL");
    assert(arraySize == STR_ARR_LEN);

    for(uint i = 0; i < arraySize; i++) {
        assert(strcmp(result_arr[i], str_add_test_case[i]) == 0 && "test_array_str failed");
    }
}

void test_array_int() {
    uint16_t arraySize;
    char ** result_arr = dap_config_get_array_str(config, "server_options", "int_arr", &arraySize);

    assert(result_arr != NULL && "test_array_str failed, result_arr is NULL");
    assert(arraySize == INT_ARR_LEN && "test_array_str failed, arraySize is not equal INT_ARR_LEN");

    for(uint i = 0; i < arraySize; i++) {
        assert(atoi(result_arr[i]) == int_arr_test_cases[i] && "test_array_int failed");
    }
}


void dap_config_tests_run() {
    printf("Start running dap_config_tests\n");
    init_test_case();

    test_config_open_fail();
    test_get_int();
    test_get_bool();
    test_array_str();
    test_array_int();

    cleanup_test_case();
}
