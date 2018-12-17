/*
 * Set utilities for networking
 */

#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

static bool LOG_VERBOSE = false;

void iputils_set_verbose(void)
{
    LOG_VERBOSE = true;
}

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
        gchar *log_str = NULL;
        va_list args;

        va_start(args, format);
        log_str = g_strdup_vprintf(format, args);
        va_end(args);

        if(log_str)
        {

            ret = printf(log_str);
            g_free(log_str);
        }
    }
    return ret;
}
