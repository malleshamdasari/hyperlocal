
// Definitions pulled from the IEEE 802.11 spec. Both are 'reserved' as of July 2015.
#define WLAN_ACTION_PUBLIC_FIELD_VALUE 128 // IEEE 802.11-2012, table 8.5.8.1
#define WLAN_ACTION_PUBLIC_RESERVED_IE 200 // IEEE 802.11-2012, table 8.4.2.1
#define AFN_BUF_MAX_LEN 1024

/*static const char AFN_SOCKNAME[] = "\0actionnotification";*/

int action_init(struct wpa_supplicant *wpa_s);
void action_notification_add_indication(struct wpabuf *buf, int pps_mo_id);
int action_rx(struct wpa_supplicant *wpa_s, const u8 *da, const u8 *sa,
			const u8 *bssid, u8 categ, const u8 *data, size_t len, int freq);

void wpa_action_req_not(void *eloop_ctx, void *timeout_ctx);
void wpa_action_cleanup(struct wpa_supplicant *wpa_s);
void wpa_action_notify_presence(struct wpa_supplicant *wpa_s, int type);