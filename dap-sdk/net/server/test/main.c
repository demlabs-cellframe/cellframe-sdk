#include "dap_common.h"
#include "dap_traffic_track_test.h"

int main(void) {
    // switch off debug info from library
    dap_log_level_set(L_CRITICAL);
    dap_traffic_track_tests_run();
    return 0;
}
