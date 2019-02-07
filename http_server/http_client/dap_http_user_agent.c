#include "dap_http_user_agent.h"
#include <string.h>

dap_http_user_agent_t* dap_http_user_agent_new(const char* a_name,
                                               const char* a_comment,
                                               unsigned short a_major_version,
                                               unsigned short a_minor_version)
{
    // TODO
    return NULL;
}

void dap_http_user_agent_delete(dap_http_user_agent_t* a_agent)
{
    // TODO
}

dap_http_user_agent_t* dap_http_user_agent_new_from_str(const char* a_user_agent_str)
{
    // TODO
    return NULL;
}

char* dap_http_user_agent_to_string(dap_http_user_agent_t* a_agent)
{
    // TODO
    return NULL;
}


void dap_http_user_agent_add_comment(dap_http_user_agent_t* a_agent, const char* comment)
{
    // TODO
}

int dap_http_user_agent_versions_compare(dap_http_user_agent_t* a_agent1,
                                         dap_http_user_agent_t* a_agent2)
{
    // TODO
    return -2;
}
