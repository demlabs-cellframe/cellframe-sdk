#include "dap_common.h"
#include "dap_strfuncs_test.h"

void dap_str_dup_test(void)
{
    int l_a = rand(), l_b = rand();
    const char *l_s = "test string";
    char l_str0[1024];
    sprintf(l_str0, "a=%d b=%d s=%s", l_a, l_b, l_s);
    char *l_str1 = dap_strdup_printf("a=%d b=%d s=%s", l_a, l_b, l_s);
    size_t str_size0 = strlen(l_str0);
    size_t str_size1 = strlen(l_str1);

    char *l_str2 = DAP_NEW_SIZE(char, str_size1 + 1);
    dap_stpcpy(l_str2, l_str1);

    size_t str_size2 = strlen(l_str2);
    dap_assert_PIF(str_size0 == str_size1, "Strings sizes must be equal");
    dap_assert_PIF(str_size1 == str_size2, "Strings sizes must be equal");

    dap_assert(!strcmp(l_str0, l_str1), "Test dap_strdup_printf()");
    dap_assert(!strcmp(l_str1, l_str2), "Test dap_stpcpy()");
    DAP_DELETE(l_str1);
    DAP_DELETE(l_str2);
}

void dap_str_modify_test(void)
{
    const char *l_s_in = "Test String";
    const char *l_s_up_check = "TEST STRING";
    const char *l_s_down_check = "test string";
    char *l_s_out;

    l_s_out = dap_strup(l_s_in, -1);
    dap_assert(!strcmp(l_s_out, l_s_up_check), "Test dap_strup()");
    DAP_DELETE(l_s_out);

    l_s_out = dap_strdown(l_s_in, -1);
    dap_assert(!strcmp(l_s_out, l_s_down_check), "Test dap_strdown()");
    DAP_DELETE(l_s_out);

    l_s_out = dap_strdup(l_s_in);
    dap_strreverse(l_s_out);
    dap_assert_PIF(strcmp(l_s_out, l_s_in), "String not modified");
    dap_strreverse(l_s_out);
    dap_assert(!strcmp(l_s_out, l_s_in), "Test dap_strreverse()");
    DAP_DELETE(l_s_out);

    l_s_out = dap_strdup_printf("      %s  ", l_s_in);
    dap_strstrip(l_s_out);
    dap_assert(!strcmp(l_s_out, l_s_in), "Test dap_strstrip()");
    DAP_DELETE(l_s_out);
}

void dap_str_array_test(void)
{
    const char *l_s_in = "1:23:: Test:  :\n:String:";
    char **l_s_array = dap_strsplit(l_s_in, ":", -1);

    int l_count = 1;
    char *l_s_tmp = dap_strstr_len(l_s_in, -1, ":");
    while(l_s_tmp) {
        l_s_tmp = dap_strstr_len(l_s_tmp + 1, -1, ":");
        l_count++;
    }

    char **l_s_array_copy = dap_strdupv(l_s_array);

    dap_assert_PIF(dap_str_countv(l_s_array) == l_count, "String split");
    dap_assert_PIF(dap_str_countv(l_s_array_copy) == l_count, "String copy");
    char *l_s_out = dap_strjoinv(":", l_s_array);
    dap_assert(!strcmp(l_s_out, l_s_in), "Test string array functions");

    dap_strfreev(l_s_array);
    dap_strfreev(l_s_array_copy);
    DAP_DELETE(l_s_out);
}

void dap_strfuncs_tests_run(void)
{
    dap_print_module_name("dap_strfuncs");

    dap_str_dup_test();
    dap_str_modify_test();
    dap_str_array_test();

    dap_usleep(0.5 * DAP_USEC_PER_SEC);
    dap_assert(1, "Test dap_usleep(0.5 sec.)");

}
