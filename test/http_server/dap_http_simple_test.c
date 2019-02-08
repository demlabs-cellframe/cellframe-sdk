#include "dap_http_simple_test.h"
#include "dap_http_simple.c"

static void test_init_deinit()
{
    dap_http_simple_set_supported_user_agents("DapVpn/2.2", "SecondVpn/3.3", NULL);

    dap_assert(_is_user_agent_supported("DapVpn/2.1") == false,
               "test lower version required");

    dap_assert(_is_user_agent_supported("DapVpn/2.2") == true,
               "test equals version required");

    dap_assert(_is_user_agent_supported("DapVpn/2.3") == true,
               "test above version required");

    dap_assert(_is_user_agent_supported("RandomName/2.3") == false,
               "test unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/3.3") == true,
               "test unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/3.4") == true,
               "test unknown user agent");

    dap_assert(_is_user_agent_supported("SecondVpn/2.2") == false,
               "test unknown user agent");
    _free_user_agents_list();
}

void dap_http_http_simple_test_run()
{
    dap_print_module_name("dap_http_http_simple_test");
    test_init_deinit();
}
