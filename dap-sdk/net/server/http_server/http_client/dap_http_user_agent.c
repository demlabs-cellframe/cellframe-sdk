#include "dap_http_user_agent.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "dap_http_user_agent"

struct dap_http_user_agent {
    char* name; // Ex: "DapVpnClient/2.2
    char* comment; // text after name
    unsigned int major_version;
    unsigned int minor_version;
    char* string_representation;
};

static char* _dap_http_user_agent_to_string(dap_http_user_agent_ptr_t a_agent)
{
    char *l_result;
    if(a_agent->comment) {
        l_result = dap_strdup_printf("%s/%d.%d %s", a_agent->name,
                a_agent->major_version, a_agent->minor_version,
                a_agent->comment);
    } else {
        l_result = dap_strdup_printf("%s/%d.%d", a_agent->name,
                a_agent->major_version, a_agent->minor_version);
    }
    return l_result;
}


dap_http_user_agent_ptr_t dap_http_user_agent_new(const char* a_name,
                                                  unsigned short a_major_version,
                                                  unsigned short a_minor_version,
                                                  const char* a_comment)
{
    if(a_name == NULL) {
        log_it(L_ERROR, "Name is NULL");
        return NULL;
    }

    dap_http_user_agent_ptr_t l_res = DAP_NEW_Z(struct dap_http_user_agent);
    l_res->name = dap_strdup(a_name);
    l_res->comment = dap_strdup(a_comment);
    l_res->major_version = a_major_version;
    l_res->minor_version = a_minor_version;
    l_res->string_representation = _dap_http_user_agent_to_string(l_res);
    return l_res;
}

void dap_http_user_agent_delete(dap_http_user_agent_ptr_t a_agent)
{
    if(a_agent != NULL) {
        DAP_DELETE(a_agent->name);
        DAP_DELETE(a_agent->comment);
        DAP_DELETE(a_agent->string_representation);
        DAP_DELETE(a_agent);
    }
}

dap_http_user_agent_ptr_t dap_http_user_agent_new_from_str(const char* a_user_agent_str)
{
    dap_http_user_agent_ptr_t l_result = NULL;
    /* Parse user agent line */
    char* user_agent_str_copy = dap_strdup(a_user_agent_str);
    char* version_line = strtok(user_agent_str_copy, " ");
    char* comment = strtok(NULL, " ");

    char* l_name = strtok(version_line, "/");

    char* l_version = strtok(NULL, "/");
    if(l_version == NULL) {
        log_it(L_ERROR, "Wrong input value %s", a_user_agent_str);
        goto END;
    }

    char* l_major = strtok(l_version, ".");
    char* l_minor = strtok(NULL, ".");
    if(l_minor == NULL) {
        log_it(L_ERROR, "Wrong input value %s", a_user_agent_str);
        goto END;
    }
    /* PARSE LINE successful */

    l_result = DAP_NEW_Z(struct dap_http_user_agent);
    l_result->name = dap_strdup(l_name);
    l_result->comment = dap_strdup(comment);
    l_result->major_version = (unsigned int) atoi(l_major);
    l_result->minor_version = (unsigned int) atoi(l_minor);

END:
    DAP_DELETE(user_agent_str_copy);
    return l_result;
}

void dap_http_user_agent_add_comment(dap_http_user_agent_ptr_t a_agent, const char *comment)
{
    if(a_agent->comment) {
        DAP_DELETE(a_agent->comment);
    }
    a_agent->comment = dap_strdup(comment);
}

static inline int _compare_versions(unsigned int a_ver1, unsigned int a_ver2)
{
    if(a_ver1 > a_ver2)
        return 1;
    if(a_ver1 < a_ver2)
        return -1;
    return 0;
}

int dap_http_user_agent_versions_compare(dap_http_user_agent_ptr_t a_agent1,
                                         dap_http_user_agent_ptr_t a_agent2)
{
    if(dap_strcmp(a_agent1->name, a_agent2->name) != 0) {
        log_it(L_ERROR, "Names not equal");
        return -3;
    }

    int l_result = _compare_versions(a_agent1->major_version, a_agent2->major_version);
    if(l_result != 0) {
        return l_result;
    }
    return _compare_versions(a_agent1->minor_version, a_agent2->minor_version);
}

unsigned int dap_http_user_agent_get_major_version(dap_http_user_agent_ptr_t a_agent)
{
    return a_agent->major_version;
}

unsigned int dap_http_user_agent_get_minor_version(dap_http_user_agent_ptr_t a_agent)
{
    return a_agent->minor_version;
}

const char* dap_http_user_agent_get_comment(dap_http_user_agent_ptr_t a_agent)
{
    return a_agent->comment;
}

const char* dap_http_user_agent_get_name(dap_http_user_agent_ptr_t a_agent)
{
    return a_agent->name;
}

char* dap_http_user_agent_to_string(dap_http_user_agent_ptr_t a_agent)
{
    return a_agent->string_representation;
}
