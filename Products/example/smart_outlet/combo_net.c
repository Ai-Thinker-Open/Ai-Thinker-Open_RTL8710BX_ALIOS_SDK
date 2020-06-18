/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */
#ifdef EN_COMBO_NET
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "aos/kernel.h"
#include <aos/yloop.h>
#include "netmgr.h"
#include "iot_export.h"
#include "iot_import.h"
#include "breeze_export.h"
#include "combo_net.h"

#define HAL_IEEE80211_IS_BEACON        ieee80211_is_beacon
#define HAL_IEEE80211_IS_PROBE_RESP    ieee80211_is_probe_resp
#define HAL_IEEE80211_GET_SSID         ieee80211_get_ssid
#define HAL_IEEE80211_GET_BSSID        ieee80211_get_bssid
#define HAL_AWSS_OPEN_MONITOR          HAL_Awss_Open_Monitor
#define HAL_AWSS_CLOSE_MONITOR         HAL_Awss_Close_Monitor
#define HAL_AWSS_SWITCH_CHANNEL        HAL_Awss_Switch_Channel

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[ETH_ALEN];
    uint8_t addr2[ETH_ALEN];
    uint8_t addr3[ETH_ALEN];
    uint16_t seq_ctrl;
    uint8_t addr4[ETH_ALEN];
};

extern char awss_running;
static breeze_apinfo_t apinfo;
static char monitor_got_bssid = 0;
static netmgr_ap_config_t config;
uint8_t g_ble_state = 0;
extern uint8_t g_ap_state;
uint8_t g_bind_state;
extern uint8_t *os_wifi_get_mac(uint8_t mac[6]);

/* Device info(five elements) will be used by ble breeze */
/* ProductKey, ProductSecret, DeviceName, DeviceSecret, ProductID */
char g_combo_pk[PRODUCT_KEY_LEN + 1] = { 0 };
char g_combo_ps[PRODUCT_SECRET_LEN + 1] = { 0 };
char g_combo_dn[DEVICE_NAME_LEN + 1] = { 0 };
char g_combo_ds[DEVICE_SECRET_LEN + 1] = { 0 };

uint32_t g_combo_pid = 0;

static void combo_status_change_cb(breeze_event_t event)
{
   switch (event) {
        case CONNECTED:
            LOG("Connected");
            g_ble_state = 1;
            break;

        case DISCONNECTED:
            LOG("Disconnected");
            g_ble_state = 0;
            aos_post_event(EV_BZ_COMBO, COMBO_EVT_CODE_RESTART_ADV, 0);
            break;

        case AUTHENTICATED:
            LOG("Authenticated");
            break;

        case TX_DONE:
            break;

        case EVT_USER_BIND:
            LOG("Ble bind");
            g_bind_state = 1;
            awss_clear_reset();
            break;

        case EVT_USER_UNBIND:
            LOG("Ble unbind");
            g_bind_state = 0;
            break;

        default:
            break;
    }
}

static void combo_set_dev_status_handler(uint8_t *buffer, uint32_t length)
{
    LOG("COM_SET:%.*s", length, buffer);
}

static void combo_get_dev_status_handler(uint8_t *buffer, uint32_t length)
{
    LOG("COM_GET:%.*s", length, buffer);
}

static void combo_apinfo_rx_cb(breeze_apinfo_t * ap)
{
    if (!ap)
        return;

    memcpy(&apinfo, ap, sizeof(apinfo));
    aos_post_event(EV_BZ_COMBO, COMBO_EVT_CODE_AP_INFO, (unsigned long)&apinfo);
}

static int combo_80211_frame_callback(char *buf, int length, enum AWSS_LINK_TYPE link_type, int with_fcs, signed char rssi)
{
    uint8_t ssid[MAX_SSID_LEN] = {0}, bssid[ETH_ALEN] = {0};
    struct ieee80211_hdr *hdr;
    int fc;
    int ret = -1;

    if (link_type != AWSS_LINK_TYPE_NONE) {
        return -1;
    }
    hdr = (struct ieee80211_hdr *)buf;

    fc = hdr->frame_control;
    if (!HAL_IEEE80211_IS_BEACON(fc) && !HAL_IEEE80211_IS_PROBE_RESP(fc)) {
        return -1;
    }
    ret = HAL_IEEE80211_GET_BSSID(hdr, bssid);
    if (ret < 0) {
        return -1;
    }
    if (memcmp(config.bssid, bssid, ETH_ALEN) != 0) {
        return -1;
    }
    ret = HAL_IEEE80211_GET_SSID(hdr, length, ssid);
    if (ret < 0) {
        return -1;
    }
    monitor_got_bssid = 1;
    strncpy(config.ssid, ssid, sizeof(config.ssid) - 1);
    HAL_AWSS_CLOSE_MONITOR();
    return 0;
}

static char is_str_asii(char *str)
{
    for (uint32_t i = 0; str[i] != '\0'; ++i) {
        if ((uint8_t) str[i] > 0x7F) {
            return 0;
        }
    }
    return 1;
}

static void combo_connect_ap(breeze_apinfo_t * info)
{
    uint64_t pre_chn_time = HAL_UptimeMs();
    int ms_cnt = 0;
    uint8_t ap_connected = 0;
    ap_scan_info_t scan_result;
    int ap_scan_result = -1;

    memset(&config, 0, sizeof(netmgr_ap_config_t));
    if (!info)
        return;

    strncpy(config.ssid, info->ssid, sizeof(config.ssid) - 1);
    strncpy(config.pwd, info->pw, sizeof(config.pwd) - 1);
    if (info->apptoken_len > 0) {
        memcpy(config.bssid, info->bssid, ETH_ALEN);
        awss_set_token(info->apptoken, info->token_type);
        if (!is_str_asii(config.ssid)) {
            LOG("SSID not asicci encode");
            HAL_AWSS_OPEN_MONITOR(combo_80211_frame_callback);
            while (1) {
                aos_msleep(50);
                if (monitor_got_bssid) {
                    break;
                }
                uint64_t cur_chn_time = HAL_UptimeMs();
                if (cur_chn_time - pre_chn_time > 250) {
                    int channel = aws_next_channel();
                    HAL_AWSS_SWITCH_CHANNEL(channel, 0, NULL);
                    pre_chn_time = cur_chn_time;
                }
            }
        }
    }
    // get region information
    if (info->region_type == REGION_TYPE_ID) {
        LOG("info->region_id: %d", info->region_id);
        iotx_guider_set_dynamic_region(info->region_id);
    } else if (info->region_type == REGION_TYPE_MQTTURL) {
        LOG("info->region_mqtturl: %s", info->region_mqtturl);
        iotx_guider_set_dynamic_mqtt_url(info->region_mqtturl);
    } else {
        LOG("REGION TYPE not supported");
        iotx_guider_set_dynamic_region(IOTX_CLOUD_REGION_INVALID);
    }
    netmgr_set_ap_config(&config);
    hal_wifi_suspend_station(NULL);
    netmgr_reconnect_wifi();

    while (ms_cnt < 30000) {
        // set connect ap timeout
        if (netmgr_get_ip_state() == false) {
            aos_msleep(500);
            ms_cnt += 500;
            LOG("wait ms_cnt(%d)", ms_cnt);
        } else {
            LOG("AP connected");
            ap_connected = 1;
            break;
        }
    }

    if (!ap_connected) {
        uint16_t err_code = 0;

        // if AP connect fail, should inform the module to suspend station
        // to avoid module always reconnect and block Upper Layer running
        hal_wifi_suspend_station(NULL);

        // if ap connect failed in specified timeout, rescan and analyse fail reason
        memset(&scan_result, 0, sizeof(ap_scan_info_t));
        LOG("start awss_apscan_process");
        ap_scan_result = awss_apscan_process(NULL, config.ssid, &scan_result);
        LOG("stop awss_apscan_process");
        if ( (ap_scan_result == 0) && (scan_result.found) ) {
            if (scan_result.rssi < -70) {
                err_code = 0xC4E1; // rssi too low
            } else {
                err_code = 0xC4E3; // AP connect fail(Authentication fail or Association fail or AP exeption)
            }
            // should set all ap info to err msg
        } else {
            err_code = 0xC4E0; // AP not found
        }

        if(g_ble_state){
            uint8_t ble_rsp[DEV_ERRCODE_MSG_MAX_LEN + 8] = {0};
            uint8_t ble_rsp_idx = 0;
            ble_rsp[ble_rsp_idx++] = 0x01;                          // Notify Code Type
            ble_rsp[ble_rsp_idx++] = 0x01;                          // Notify Code Length
            ble_rsp[ble_rsp_idx++] = 0x02;                          // Notify Code Value, 0x02-fail
            ble_rsp[ble_rsp_idx++] = 0x03;                          // Notify SubErrcode Type
            ble_rsp[ble_rsp_idx++] = sizeof(err_code);              // Notify SubErrcode Length
            memcpy(ble_rsp + ble_rsp_idx, (uint8_t *)&err_code, sizeof(err_code));  // Notify SubErrcode Value
            ble_rsp_idx += sizeof(err_code);
            breeze_post(ble_rsp, ble_rsp_idx);
        }
    }
}

static void combo_service_evt_handler(input_event_t * event, void *priv_data)
{
    if (event->type != EV_BZ_COMBO) {
        return;
    }

    if (event->code == COMBO_EVT_CODE_AP_INFO) {
        awss_running = 1;
        combo_connect_ap((breeze_apinfo_t *) event->value);
    } else if (event->code == COMBO_EVT_CODE_RESTART_ADV) {
        breeze_stop_advertising();
        aos_msleep(500); // wait for adv stop
        breeze_start_advertising(g_ap_state?4:3, g_bind_state, g_bind_state);
    }
}

static int reverse_byte_array(uint8_t *byte_array, int byte_len) {
    uint8_t temp = 0;
    int i = 0;
    if (!byte_array) {
        LOG("reverse_mac invalid params!");
        return -1;
    }
    for (i = 0; i < (byte_len / 2); i++) {
        temp = byte_array[i];
        byte_array[i] = byte_array[byte_len - i - 1];
        byte_array[byte_len - i - 1] = temp;
    }
    return 0;
}

int combo_net_init()
{
    breeze_dev_info_t dinfo = { 0 };
    int len;

    len = sizeof(g_combo_pk);
    vendor_get_product_key(g_combo_pk, &len);

    len = sizeof(g_combo_ps);
    vendor_get_product_secret(g_combo_ps, &len);

    len = sizeof(g_combo_dn);
    vendor_get_device_name(g_combo_dn, &len);

    len = sizeof(g_combo_ds);
    vendor_get_device_secret(g_combo_ds, &len);

    vendor_get_product_id(&g_combo_pid);

    aos_register_event_filter(EV_BZ_COMBO, combo_service_evt_handler, NULL);
	g_bind_state = breeze_get_bind_state();
    if ((strlen(g_combo_pk) > 0) && (strlen(g_combo_ps) > 0)
            && (strlen(g_combo_dn) > 0) && (strlen(g_combo_ds) > 0) && g_combo_pid > 0) {
        uint8_t combo_adv_mac[6] = {0};
        os_wifi_get_mac(combo_adv_mac);
        // Set wifi mac to breeze awss adv, to notify app this is a wifi dev
        // Awss use wifi module device info.
        // Only use BT mac when use breeze and other bluetooth communication functions
        reverse_byte_array(combo_adv_mac, 6);
        dinfo.product_id = g_combo_pid;
        dinfo.product_key = g_combo_pk;
        dinfo.product_secret = g_combo_ps;
        dinfo.device_name = g_combo_dn;
        dinfo.device_secret = g_combo_ds;
        dinfo.dev_adv_mac = combo_adv_mac;
        breeze_awss_init(&dinfo,
                         combo_status_change_cb,
                         combo_set_dev_status_handler,
                         combo_get_dev_status_handler,
                         combo_apinfo_rx_cb,
                         NULL);
        breeze_awss_start();
        breeze_start_advertising(g_ap_state?4:3, g_bind_state, g_bind_state);
    } else {
        LOG("combo device info not set!");
    }
    return 0;
}

int combo_net_deinit()
{
    breeze_awss_stop();
    return 0;
}

uint8_t combo_ble_conn_state(void)
{
    return g_ble_state;
}

uint8_t combo_get_bind_state(void)
{
    return 0;
}

uint8_t combo_get_ap_state(void)
{
    return 0;
}

#endif