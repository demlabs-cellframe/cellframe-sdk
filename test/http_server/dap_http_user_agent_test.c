#include "dap_http_user_agent_test.h"


static void dap_http_user_agent_test_new_delete()
{
    dap_http_user_agent_ptr_t agent =
            dap_http_user_agent_new("DapVpn", 2, 3, NULL);

    dap_assert(dap_http_user_agent_get_major_version(agent) == 2, "Major version");
    dap_assert(dap_http_user_agent_get_minor_version(agent) == 3, "Minor version");

    dap_http_user_agent_delete(agent);
    dap_pass_msg("Allocate and delete object");
}

static void dap_http_user_agent_test_new_from_string()
{
    const char* user_agent_string = "DapVpn/23.32 somecomment";

    dap_http_user_agent_ptr_t agent =
            dap_http_user_agent_new_from_str(user_agent_string);

    dap_assert(dap_http_user_agent_get_major_version(agent) == 23,
               "Check major version");
    dap_assert(dap_http_user_agent_get_minor_version(agent) == 32,
               "Check minor version");

    dap_assert(dap_str_equals(dap_http_user_agent_get_name(agent), "DapVpn"),
               "Check agent name");
    dap_assert(dap_str_equals(dap_http_user_agent_get_comment(agent), "somecomment"),
               "Check comment");

    dap_http_user_agent_delete(agent);
    dap_pass_msg("dap_http_user_agent_test_new_from_string");
}

static void dap_http_user_agent_test_new_from_string_without_comment()
{
    const char* user_agent_string = "DapVpn/23.32";

    dap_http_user_agent_ptr_t agent =
            dap_http_user_agent_new_from_str(user_agent_string);

    dap_assert(dap_http_user_agent_get_major_version(agent) == 23,
               "Check major version");
    dap_assert(dap_http_user_agent_get_minor_version(agent) == 32,
               "Check minor version");

    dap_assert(dap_str_equals(dap_http_user_agent_get_name(agent), "DapVpn"),
               "Check agent name");
    dap_assert(dap_http_user_agent_get_comment(agent) == NULL,
               "Check comment");

    dap_http_user_agent_delete(agent);
    dap_pass_msg("dap_http_user_agent_test_new_from_string_without_comment");
}

static void dap_http_user_agent_test_to_string()
{
    dap_http_user_agent_ptr_t agent =
            dap_http_user_agent_new("DapVpn", 2, 3, "Comment");
    const char* expected_string = "DapVpn/2.3 Comment";
    const char* result = dap_http_user_agent_to_string(agent);

    dap_assert(dap_str_equals(expected_string, result), result);

    dap_http_user_agent_delete(agent);

    dap_pass_msg("Allocate and delete object");
}

static void dap_http_user_agent_test_to_string_without_comment()
{
    dap_http_user_agent_ptr_t agent =
            dap_http_user_agent_new("DapVpn", 2, 3, NULL);
    const char* expected_string = "DapVpn/2.3";
    const char* result = dap_http_user_agent_to_string(agent);

    dap_assert(dap_str_equals(expected_string, result), result);

    dap_http_user_agent_delete(agent);

    dap_pass_msg("Allocate and delete object");
}

static void dap_http_user_agent_test_compare_versions()
{
    dap_http_user_agent_ptr_t agent1 =
            dap_http_user_agent_new("DapVpn", 2, 3, NULL);

    dap_http_user_agent_ptr_t agent2 =
            dap_http_user_agent_new("DapVpn", 2, 4, NULL);

    dap_http_user_agent_ptr_t agent3 =
            dap_http_user_agent_new("DapVpn", 3, 1, NULL);
    dap_http_user_agent_ptr_t agent4 =
            dap_http_user_agent_new("OterName", 3, 11, NULL);


    int result = dap_http_user_agent_versions_compare(agent1, agent4);
    dap_assert(result == -3, "Checks different names");

    result = dap_http_user_agent_versions_compare(agent1, agent2);
    dap_assert(result == -1, "Checks agent1, agent2(above))");

    result = dap_http_user_agent_versions_compare(agent1, agent1);
    dap_assert(result == 0, "Checks agent1, agent1");

    result = dap_http_user_agent_versions_compare(agent3, agent2);
    dap_assert(result == 1, "Checks agent3(above major), agent2");

    result = dap_http_user_agent_versions_compare(agent2, agent1);
    dap_assert(result == 1, "Checks agent3(above major), agent2");


    dap_http_user_agent_delete(agent1);
    dap_http_user_agent_delete(agent2);
    dap_http_user_agent_delete(agent3);
    dap_http_user_agent_delete(agent4);

    dap_pass_msg("Allocate and delete object");
}

void dap_http_user_agent_test_run(void)
{
    dap_print_module_name("dap_http_user_agent");
    dap_http_user_agent_test_new_delete();
    dap_http_user_agent_test_new_from_string();
    dap_http_user_agent_test_new_from_string_without_comment();
    dap_http_user_agent_test_to_string();
    dap_http_user_agent_test_to_string_without_comment();
    dap_http_user_agent_test_compare_versions();
}
