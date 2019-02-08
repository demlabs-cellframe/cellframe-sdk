#include "dap_common.h"
#include "dap_http_user_agent_test.h"
#include "dap_http_simple_test.h"

int main(void) {
    // switch off debug info from library
    set_log_level(L_CRITICAL);
    dap_http_user_agent_test_run();
    dap_http_http_simple_test_run();
    return 0;
}
