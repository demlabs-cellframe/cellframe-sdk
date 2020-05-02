#include "dap_common.h"
#include "dap_strfuncs_test.h"
#include "dap_list.h"
#include "dap_string.h"

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

    size_t l_count = 1;
    char *l_s_tmp = dap_strstr_len(l_s_in, -1, ":");
    while(l_s_tmp) {
        l_s_tmp = dap_strstr_len(l_s_tmp + 1, -1, ":");
        l_count++;
    }

    char **l_s_array_copy = dap_strdupv((const char**)l_s_array);

    dap_assert_PIF(dap_str_countv(l_s_array) == l_count, "String split");
    dap_assert_PIF(dap_str_countv(l_s_array_copy) == l_count, "String copy");
    char *l_s_out = dap_strjoinv(":", l_s_array);
    dap_assert(!strcmp(l_s_out, l_s_in), "Test string array functions");

    dap_strfreev(l_s_array);
    dap_strfreev(l_s_array_copy);
    DAP_DELETE(l_s_out);
}

static void list_delete(void* a_pointer)
{
    DAP_DELETE(a_pointer);
}

void dap_list_test(void)
{
    dap_list_t *l_list = NULL;
    l_list = dap_list_append(l_list, "item 1");
    l_list = dap_list_append(l_list, "item 2");
    l_list = dap_list_append(l_list, "item 3");
    l_list = dap_list_prepend(l_list, "item 0");

    dap_list_t *l_list_tmp = dap_list_find(l_list, "item 2");
    unsigned int l_count = dap_list_length(l_list);
    dap_list_remove(l_list, "item 3");
    unsigned int l_count_after = dap_list_length(l_list);

    dap_assert_PIF(l_count == 4, "Test dap_list_length()");
    dap_assert_PIF(l_count_after == 3, "Test dap_list_remove()");
    dap_assert_PIF(!strcmp(l_list_tmp->data, "item 2"), "Test dap_list_find()");
    dap_list_free(l_list);

    // for test dap_list_free_full()
    l_list = NULL;
    l_list = dap_list_append(l_list, dap_strdup("item 1"));
    l_list = dap_list_append(l_list, dap_strdup("item 2"));

    dap_assert(l_list, "Test dap_list_t");
    dap_list_free_full(l_list, list_delete);
}

void dap_string_test(void)
{
    dap_string_t *l_str = dap_string_new(NULL);
    dap_string_append(l_str, "str=string 1");
    dap_assert_PIF(!strcmp(l_str->str, "str=string 1"), "Test dap_string_append()");

    dap_string_append_printf(l_str, " int=%d", 123);
    dap_assert_PIF(!strcmp(l_str->str, "str=string 1 int=123"), "Test dap_string_append()");

    dap_string_erase(l_str, 3, 9);
    dap_assert_PIF(!strcmp(l_str->str, "str int=123"), "Test dap_string_erase()");

    dap_string_append_len(l_str, " string2", strlen(" string2"));
    dap_assert_PIF(!strcmp(l_str->str, "str int=123 string2"), "Test dap_string_append_len()");

    dap_assert(l_str, "Test dap_string_t");
    dap_string_free(l_str, true);
}

void dap_strfuncs_tests_run(void)
{
    dap_print_module_name("dap_strfuncs");

    dap_str_dup_test();
    dap_str_modify_test();
    dap_str_array_test();
    dap_list_test();
    dap_string_test();

    dap_usleep(0.5 * DAP_USEC_PER_SEC);
    dap_assert(1, "Test dap_usleep(0.5 sec.)");

}
