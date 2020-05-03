#include "dap_http_simple_test.h"
#include "dap_http_simple.c"

static void test_user_agent_support()
{
    dap_http_simple_set_supported_user_agents("DapVpn/2.2", "SecondVpn/3.3", NULL);

    dap_assert(_is_user_agent_supported("DapVpn/2.1") == false,
               "Lower version required");

    dap_assert(_is_user_agent_supported("DapVpn/2.2") == true,
               "Equals version required");

    dap_assert(_is_user_agent_supported("DapVpn/2.3") == true,
               "Above version required");

    dap_assert(_is_user_agent_supported("RandomName/2.3") == false,
               "Unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/3.3") == true,
               "Unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/3.4") == true,
               "Unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/2.2") == false,
               "Unknown user agent");

    dap_assert(_is_supported_user_agents_list_setted() == true,
               "_is_supported_user_agents_setted");
    _free_user_agents_list();
}

static void test_init_deinit()
{
    dap_http_simple_module_init();
    dap_http_simple_module_deinit();
    dap_pass_msg("init => deinit");
}

static void test_is_supported_empty_list()
{
    dap_assert(_is_supported_user_agents_list_setted() == false,
               "_is_supported_user_agents_setted empty");
}

void dap_http_http_simple_test_run()
{
    dap_print_module_name("dap_http_http_simple_test");
    test_user_agent_support();
    test_init_deinit();
    test_is_supported_empty_list();
}
