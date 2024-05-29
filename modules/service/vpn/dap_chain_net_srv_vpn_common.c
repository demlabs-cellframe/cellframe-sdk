
#include "dap_chain_net_srv_vpn_common.h"
#include "dap_chain_ledger.h"


static bool s_tag_check_vpn(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    
    //VPN  open: have SRV_PAY out with vpn uid
    
    if (a_items_grp->items_out_cond_srv_pay) {
        dap_chain_tx_out_cond_t *l_cond_out = a_items_grp->items_out_cond_srv_pay->data; 
        if (l_cond_out->header.srv_uid.uint64 == DAP_CHAIN_NET_SRV_VPN_ID)
           if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_OPEN;
        return true;
    }
    
    //VPN native use: have IN_COND linked with DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY out with vpn uid
    
    if (a_items_grp->items_in_cond) {
       for (dap_list_t *it = a_items_grp->items_in_cond; it; it = it->next) {
            dap_chain_tx_in_cond_t *l_tx_in = it->data;
            dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(a_ledger, l_tx_in);

            if (l_tx_out_cond && 
                l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY &&
                l_tx_out_cond->header.srv_uid.uint64 == DAP_CHAIN_NET_SRV_VPN_ID) {
                    if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_USE;
                    return true;
            }
        }
    }

    return false;
}



int dap_chain_net_srv_vpn_pre_init()
{
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_ledger_service_add(l_uid, "vpn", s_tag_check_vpn);
    return 0;
}
