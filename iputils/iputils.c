/*
 * Set utilities for networking
 */

#include <stdio.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_strfuncs.h"

static bool LOG_VERBOSE = false;

/**
 * Set verbose mode
 */
void iputils_set_verbose(void)
{
    LOG_VERBOSE = true;
}

/**
 * Reset verbose mode
 */
void iputils_reset_verbose(void)
{
    LOG_VERBOSE = false;
}

// analog printf()
int log_printf(const char *format, ...)
{
    int ret = 0;
    if(LOG_VERBOSE)
    {
        char *log_str = NULL;
        va_list args;

        va_start(args, format);
        log_str = dap_strdup_vprintf(format, args);
        va_end(args);

        if(log_str)
        {

            ret = printf("%s", log_str);
            DAP_DELETE(log_str);
        }
    }
    return ret;
}
