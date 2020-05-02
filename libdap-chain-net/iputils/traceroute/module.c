/*
 Copyright (c)  2006, 2007		Dmitry Butskoy
 <buc@citadel.stu.neva.ru>
 License:  GPL v2 or any later

 See COPYING for the status of this software.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "traceroute.h"

void tr_module_icmp_insert();
void tr_module_udp_insert();
void tr_module_tcp_insert();
void tr_module_tcpconn_insert();
void tr_module_raw_insert();
void tr_module_dccp_insert();

static tr_module *base = NULL;

void tr_register_module(tr_module *ops) {

    ops->next = base;
    base = ops;
//    printf("tr_register_module name=%s\n", ops->name);
}

const tr_module *tr_get_module(const char *name) {
    const tr_module *ops;

    tr_module_icmp_insert();
    tr_module_udp_insert();
    tr_module_tcp_insert();
    tr_module_tcpconn_insert();
    tr_module_raw_insert();
    tr_module_dccp_insert();

    if(!name)
        return 0;

    for(ops = base; ops; ops = ops->next) {
        if(!strcasecmp(name, ops->name))
            return ops;
    }

    return NULL;
}
