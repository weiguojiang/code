/*
 * ovs_debug.c
 *
 *  Created on: 2015/9/9
 *      Author:
 */

#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "ovs_debug.h"

#define SE_DP_INDEX_INVALID   -1

static CVMX_SHARED struct se_log_switch g_debug_switch =
{
    .index = SE_DP_INDEX_INVALID,
    .log_switch = SE_DEBUG_LEVEL_NONE
};


unsigned int get_debug_switch(void) {
    return g_debug_switch.log_switch;
}
bool check_log_index(int index) {
    return (g_debug_switch.index == index);
}

static char * get_exist_debug_name(unsigned int debug) {
    char *debug_name;

    switch(debug) {
        case SE_DEBUG_LEVEL_INFO:
        {
            debug_name = "debug info";
            break;
        }
        case SE_DEBUG_LEVEL_WARN:
        {
            debug_name = "debug warn";
            break;
        }
        case SE_DEBUG_LEVEL_ERROR:
        {
            debug_name = "debug error";
            break;
        }
        case SE_DEBUG_LEVEL_ALL:
        {
            debug_name = "all debug";
            break;
        }
        default :
        {
            debug_name = "none";
            break;
        }
    }
    return debug_name;
}

void open_debug_switch(int index, enum debug_level log_switch) {
    if (g_debug_switch.log_switch) {
        printf("Please close %s switch first", get_exist_debug_name(g_debug_switch.log_switch));
        return;
    }
    if (SE_DEBUG_LEVEL_ALL & log_switch) {
        g_debug_switch.log_switch |= log_switch;
        g_debug_switch.index = index;
    }
    return;
}
void close_debug_switch(int index) {

    if (g_debug_switch.index == SE_DP_INDEX_INVALID) {
        printf("There's none debug switch open yet.\n");
        return;
    }
    g_debug_switch.log_switch = SE_DEBUG_LEVEL_NONE;
    g_debug_switch.index = SE_DP_INDEX_INVALID;
    return;
}
