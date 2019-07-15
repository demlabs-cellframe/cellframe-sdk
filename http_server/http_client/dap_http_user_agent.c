#include "dap_http_user_agent.h"
#include "dap_common.h"
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
    char * result = calloc(1, sizeof(*a_agent));

    if(a_agent->comment) {
        dap_sprintf(result, "%s/%d.%d %s", a_agent->name,
                a_agent->major_version, a_agent->minor_version,
                a_agent->comment);
    } else {
        dap_sprintf(result, "%s/%d.%d", a_agent->name,
                a_agent->major_version, a_agent->minor_version);
    }

    return result;
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

    dap_http_user_agent_ptr_t res = DAP_NEW_Z(struct dap_http_user_agent);
    res->name = strdup(a_name);
    res->comment = a_comment ? strdup(a_comment) : NULL;
    res->major_version = a_major_version;
    res->minor_version = a_minor_version;
    res->string_representation = _dap_http_user_agent_to_string(res);
    return res;
}

void dap_http_user_agent_delete(dap_http_user_agent_ptr_t a_agent)
{
    free(a_agent->name);
    free(a_agent->comment);
    free(a_agent->string_representation);
    free(a_agent);
}

dap_http_user_agent_ptr_t dap_http_user_agent_new_from_str(const char* a_user_agent_str)
{
    dap_http_user_agent_ptr_t result = NULL;
    /* Parse user agent line */
    char* user_agent_str_copy = strdup(a_user_agent_str);
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

    result = DAP_NEW_Z(struct dap_http_user_agent);
    result->name = strdup(l_name);
    result->comment = comment ? strdup(comment) : NULL;
    result->major_version = (unsigned int) atoi(l_major);
    result->minor_version = (unsigned int) atoi(l_minor);

END:
    free(user_agent_str_copy);
    return result;
}

void dap_http_user_agent_add_comment(dap_http_user_agent_ptr_t a_agent, const char* comment)
{
    // TODO
}

static inline int _compare_versions(unsigned int ver1, unsigned int ver2)
{
    if(ver1 > ver2)
        return 1;
    if(ver1 < ver2)
        return -1;
    return 0;
}

int dap_http_user_agent_versions_compare(dap_http_user_agent_ptr_t a_agent1,
                                         dap_http_user_agent_ptr_t a_agent2)
{
    if(strcmp(a_agent1->name, a_agent2->name) != 0) {
        log_it(L_ERROR, "Names not equal");
        return -3;
    }

    int result = _compare_versions(a_agent1->major_version, a_agent2->major_version);
    if(result != 0) return result;
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
