#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_bridge.h"
#include "dap_chain_bridge_btc.h"

#define LOG_TAG "dap_chain_bridge_btc"

typedef struct dap_chain_bridge_btc_pvt{
    dap_chain_net_t * net;
    const char * profile;
    const char * wallet;
    const char * network;
    double  stake_min, stake_max;
} dap_chain_bridge_btc_pvt_t;

static int s_bridge_callback_init(const char * a_bridge_name, dap_chain_net_t * a_net, dap_config_t * a_cfg);

int dap_chain_bridge_btc_init()
{
    dap_chain_bridge_register("bridge-btc", s_bridge_callback_init);
    return 0;
}

void dap_chain_bridge_btc_deinit()
{

}

static int s_bridge_callback_init(const char * a_bridge_name, dap_chain_net_t * a_net, dap_config_t * a_cfg)
{
    dap_chain_bridge_btc_pvt_t * l_btc_pvt = DAP_NEW_Z(dap_chain_bridge_btc_pvt_t);
    l_btc_pvt->net = a_net;
    l_btc_pvt->profile = dap_config_get_item_str_default(a_cfg , a_bridge_name , "profile","emercoin" );
    l_btc_pvt->wallet = dap_config_get_item_str(a_cfg , a_bridge_name , "wallet");
    l_btc_pvt->network = dap_config_get_item_str_default(a_cfg , a_bridge_name , "network", "testnet" );
    l_btc_pvt->stake_min = dap_config_get_item_double_default(a_cfg , a_bridge_name , "stake_min", -1.0);
    l_btc_pvt->stake_max = dap_config_get_item_double_default(a_cfg , a_bridge_name , "stake_max", -1.0);
    return 0;
}
