/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef EN_COMBO_NET

#ifndef __COMBO_NET_H__
#define __COMBO_NET_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#define COMBO_EVT_CODE_AP_INFO         0x0001
#define COMBO_EVT_CODE_RESTART_ADV     0x0002

int combo_net_init(void);
int combo_net_deinit(void);
uint8_t combo_ble_conn_state(void);

#endif
#endif