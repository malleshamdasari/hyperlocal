#include "utils/includes.h"

#ifdef CONFIG_ACTION_NOTIFICATION

#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <dirent.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "drivers/driver.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "ap_config.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "ap_action.h"

struct not_ctrl_dst {
	struct sockaddr_un addr;
	socklen_t addrlen;
	int errors;
};

struct afq_mes{
	char *payload;
	size_t paylen;
	u8 type;
	u32 mid;
	struct afq_mes *next;
};

struct afq {
	u8 addr[ETH_ALEN];
	u32 last_bcst_mes_id;
	int computed;
	struct afq_mes *pending;
	struct afq_mes *last;
	struct afq *next;
};

static int stop_not_connection(struct hostapd_data *hapd, struct sockaddr_un *addr, socklen_t addrlen);
static void hapd_not_node_timeout(void *eloop_ctx, void *timeout_ctx);
static void hapd_not_brct_timeout(void *eloop_ctx, void *timeout_ctx);

static int getLoc(const u8 *addr){
	int loc;

	if (is_broadcast_ether_addr(addr)){
		loc = 0;
	}else{
		loc = STA_HASH(addr) + 1;
	}

	return loc;
}

static struct afq *getNode(struct hostapd_data *hapd,
					 const u8 *addr){
	struct afq *node;

	int loc = getLoc(addr);

	node = hapd->pend_list[loc];

	while (node != NULL && os_memcmp(node->addr, addr, ETH_ALEN) != 0){
		node = node->next;
	}

	return node;

}

static struct afq *addNode(struct hostapd_data *hapd,
					const u8 *addr){
	struct afq *node;
	int loc;

	node = os_malloc(sizeof(struct afq));
	if (node == NULL) {
		wpa_printf(MSG_ERROR, "malloc failed");
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "Adding new node for " MACSTR, MAC2STR(addr));

	os_memcpy(node->addr, addr, ETH_ALEN);
	node->pending = NULL;
	node->last = NULL;
	node->last_bcst_mes_id = 0;
	node->computed = 0;

	loc = getLoc(addr);

	node->next = hapd->pend_list[loc];
	hapd->pend_list[loc] = node;

	wpa_printf(MSG_DEBUG, "Head: %p, Next: %p", node, node->next);

	return node;

}

static struct wpabuf * hostapd_gen_action_resp(struct afq_mes *mes, const u16 num){
	struct wpabuf *buf;
	buf = wpabuf_alloc(4096);
	if (buf == NULL){
		return NULL;
	}

	wpa_printf(MSG_INFO, "Preparing action frame for message id %u", mes->mid);

	wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_GAS_INITIAL_RESP);
	wpabuf_put_u8(buf, 255);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_NOTIFICATION);
	wpabuf_put_u8(buf, mes->type);
	wpabuf_put_le32(buf, mes->mid);
	wpabuf_put_le16(buf, strlen(mes->payload));
	wpabuf_put_data(buf, mes->payload, mes->paylen);
	wpabuf_put_le16(buf, num);

	return buf;
}

static void hapd_not_iface_send(struct hostapd_data *hapd,
								const char *cmd, size_t cmdlen,
								const char *buf, size_t buflen)
{
	struct iovec io[2];
	struct msghdr msg;
	struct not_ctrl_dst *dst;

	wpa_printf(MSG_DEBUG, "cmd: %s, cmdlen: %u", cmd, cmdlen);
	wpa_printf(MSG_DEBUG, "buf: %s, buflen: %u", buf, buflen);

	if (hapd->not_dst == NULL || hapd->not_sock < 0){
		char mbuf[2048];
		os_snprintf(mbuf,sizeof(mbuf), "%s %s", cmd, buf);
		wpa_printf(MSG_DEBUG, "No notification unit, message sent thruough hostapd channels");
		wpa_msg(hapd->msg_ctx, MSG_INFO, mbuf);
	}else{
		dst = hapd->not_dst;

		io[0].iov_base = (char *) cmd;
		io[0].iov_len = cmdlen;
		io[1].iov_base = (char *) buf;
		io[1].iov_len = buflen;
		os_memset(&msg, 0, sizeof(msg));
		msg.msg_iov = io;
		msg.msg_iovlen = 2;
		msg.msg_name = &dst->addr;
		msg.msg_namelen = dst->addrlen;

		if (sendmsg(hapd->not_sock, &msg, 0) < 0){
			int _errno = errno;
			wpa_printf(MSG_ERROR, "NOTIFICATION IFACE error: %d - %s", errno, strerror(errno));
			dst->errors++;
			if (dst->errors > 10 || _errno == ENOENT){
				stop_not_connection(hapd, &dst->addr, dst->addrlen);
			}
		}else{
			wpa_printf(MSG_DEBUG, "Message sent for handling %s, %s", cmd, buf);
			dst->errors = 0;
		}
	}
}

static void notify(struct hostapd_data *hapd, const u8 *addr, u32 mid, int type){
	char cmd[1024];
	char buf[1024];
	int cmdlen, buflen;

	cmdlen = os_snprintf(cmd, 1023, "SENDMSG");
	if(cmdlen < 0 || cmdlen > 1023){
		return;
	}

	buflen = os_snprintf(buf, 1023, "Addr:" MACSTR " MID:%u Type:%d", MAC2STR(addr), mid, type);

	if(buflen < 0 || buflen > 1023){
		return;
	}

	hapd_not_iface_send(hapd, cmd, cmdlen, buf, buflen);

}

static void hapd_not_indicate_tout(struct hostapd_data *hapd,
										const u8 *addr)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(4096);
	if (buf == NULL){
		return;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_GAS_INITIAL_RESP);
	wpabuf_put_u8(buf, 255);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_NOTIFICATION_IND);

	wpabuf_put_le16(buf, hapd->mtout);

	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
								wpabuf_head(buf), wpabuf_len(buf)))
		wpa_printf(MSG_ERROR, "send afn indication: indicator not sent to " MACSTR, MAC2STR(addr));

	wpa_printf(MSG_DEBUG, "Indicator request is sent to " MACSTR, MAC2STR(addr));

	os_free(buf);
}

static void compute_notification_for_sta(struct hostapd_data *hapd,
										 const u8 *addr)
{
	char hwaddr[256];
	char cmd[32];
	int hwlen;
	int cmdlen;

	hwlen = os_snprintf(hwaddr, 256, "Addr:" MACSTR, MAC2STR(addr));
	cmdlen = os_snprintf(cmd, 32, "%s", "NEWNODE");

	wpa_printf(MSG_DEBUG, "Informing the handling unit about the new node " MACSTR, MAC2STR(addr));
	hapd_not_iface_send(hapd, cmd, cmdlen, hwaddr, hwlen);

}

static void send_broadcast_messages(struct hostapd_data *hapd,
							   struct afq *node, const u16 num){
	struct wpabuf *actresp;

	struct afq *brdcst;
	struct afq_mes *mes;

	brdcst = hapd->pend_list[0];

	mes = brdcst->pending;
	while (mes){
		if (node->last_bcst_mes_id < mes->mid){
			actresp = hostapd_gen_action_resp(mes, num);

			wpa_printf(MSG_DEBUG, "Sending a broadcast notification %u to " MACSTR, mes->mid, MAC2STR(node->addr));

			if (actresp) {
				if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, node->addr,
											wpabuf_head(actresp), wpabuf_len(actresp)))
					wpa_printf(MSG_ERROR, "action frame notification not sent to " MACSTR, MAC2STR(node->addr));
			}
			node->last_bcst_mes_id = mes->mid;

			notify(hapd, node->addr, mes->mid, 0);

			os_free(actresp);

		}else{
			wpa_printf(MSG_DEBUG, "Broadcast notification %u already sent to " MACSTR, mes->mid, MAC2STR(node->addr));
		}
		mes = mes->next;
	}

}

static void send_node_messages(struct hostapd_data *hapd,
							   struct afq *node){
	struct wpabuf *actresp;
	struct afq_mes *mes, *idx;

	if (node == NULL){
		wpa_printf(MSG_ERROR, "There is no node ");
		return;
	}

	mes = node->pending;
	while (mes){

		actresp = hostapd_gen_action_resp(mes, 0);
		if (actresp) {
			wpa_printf(MSG_DEBUG, "Sending a directed notification %u to " MACSTR, mes->mid, MAC2STR(node->addr));
			if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, node->addr,
										wpabuf_head(actresp), wpabuf_len(actresp)))
				wpa_printf(MSG_ERROR, "action frame notification not sent to " MACSTR, MAC2STR(node->addr));

		}
		notify(hapd, node->addr, mes->mid, 0);
		idx = mes;
		mes = mes->next;
		node->pending = mes;

		os_free(idx->payload);
		os_free(idx);
		os_free(actresp);

	}
}

static void send_new_broadcast_message(struct hostapd_data *hapd, struct afq_mes *mes){
	struct afq *node;
	struct wpabuf *actresp;
	struct sta_info *sta;

	wpa_printf(MSG_DEBUG, "New broadcast notification is registered with id %u", mes->mid);

	actresp = hostapd_gen_action_resp(mes, 0);
	if (actresp == NULL)
		return;

	for (sta = hapd->sta_list; sta; sta = sta->next) {
		node = getNode(hapd, sta->addr);
		if (node){
			wpa_printf(MSG_DEBUG, "Message %u is being sent to " MACSTR, mes->mid, MAC2STR(node->addr));
			if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, node->addr,
										wpabuf_head(actresp), wpabuf_len(actresp))){
				wpa_printf(MSG_ERROR, "action frame notification not sent to " MACSTR, MAC2STR(node->addr));
				continue;
			}
			node->last_bcst_mes_id = mes->mid;
		}
	}

	os_free(actresp);

}

void send_buffered_push_messages(struct hostapd_data *hapd,
								 const u8 *addr, const u16 num){

	struct afq *node;
	struct sta_info *sta;

	if(is_broadcast_ether_addr(addr))
		return;

	node = getNode(hapd, addr);

	if (node == NULL){
		wpa_printf(MSG_DEBUG, "First time for " MACSTR, MAC2STR(addr));
		node = addNode(hapd, addr);
	}

	if(node == NULL){
		return;
	}

	if (node->computed == 0){
		if(hapd->fastnot){
			hapd_not_indicate_tout(hapd, addr);
			wpa_printf(MSG_DEBUG, "Tell the new node " MACSTR " to send something for directed messages", MAC2STR(addr));
		}

		wpa_printf(MSG_DEBUG, "Computing notifications for " MACSTR, MAC2STR(addr));
		compute_notification_for_sta(hapd, addr);
		node->computed = 1;
	}

	eloop_cancel_timeout(hapd_not_node_timeout, hapd, node);
	if ((sta = ap_get_sta(hapd, addr)) == NULL){
		eloop_register_timeout(hapd->ntout, 0, hapd_not_node_timeout,
							   hapd, node);
	}

	wpa_printf(MSG_DEBUG, "Sending broadcast notifications to " MACSTR, MAC2STR(addr));
	send_broadcast_messages(hapd, node, num);

	wpa_printf(MSG_DEBUG, "Sending directed notifications to " MACSTR, MAC2STR(addr));
	send_node_messages(hapd, node);
}

/*static int hostapd_not_probe_req_rx(void *ctx, const u8 *addr, const u8 *da,
									const u8 *bssid,
									const u8 *ie, size_t ie_len,
									int ssi_signal){
	struct hostapd_data *hapd = ctx;
	struct ieee802_11_elems elems;

	if (ieee802_11_parse_elems(ie, ie_len, &elems, 0) == ParseFailed) {
		wpa_printf(MSG_ERROR, "Notification: Could not parse ProbeReq from "
				   MACSTR, MAC2STR(addr));
		return -1;
	}

	if (elems.afn) {
		u16 num = WPA_GET_LE16(elems.afn);
		wpa_printf(MSG_DEBUG, MACSTR " is capable of notifications, sending messages now", MAC2STR(addr));
		send_buffered_push_messages(hapd, addr, num);
	}


	return 0;
}*/

u8 * hostapd_eid_afn_indication(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	//if(hapd->fastnot == 0)
	//	return eid;

	*pos++ = WLAN_EID_NOT_INDICATOR;
	*pos++ = 2;

	WPA_PUT_LE16(pos, hapd->mtout);

	pos += 2;

	wpa_printf(MSG_DEBUG, "action handler: afn indication\n");
	return pos;
}


int afn_pending_append(struct hostapd_data *hapd, const char *cmd,
					   char *buf, size_t buflen)
{
	u8 addr[ETH_ALEN];
	struct afq_mes *outgoing;
	struct afq *node;
	const char *ptr, *p2;
	size_t len;
	int addr_len;
	int type;
	int ret = 0;
	char *end = buf + buflen;

	ptr = cmd;

	addr_len = hwaddr_aton2(ptr, addr);
	if (addr_len < 0)
		return -1;

	ptr += addr_len;
	if(*ptr++ != ' ')
		return -1;

	type = *ptr - '0';
	if (type < 0 || type > 1){
		wpa_printf(MSG_ERROR, "Undefined message type");
		ret = -1;
	}
	type += WLAN_PA_NO_RESP;
	ptr++;
	if(*ptr++ != ' ')
		return -1;

	if(ptr == NULL){
		wpa_printf(MSG_ERROR, "No message given");
		return -1;
	}

	p2 = os_strstr(ptr, ":ENDNOT:");

	if(p2 == NULL)
		len = os_strlen(ptr);
	else
		len = p2 - ptr -1;

	if (len <= 0){
		wpa_printf(MSG_ERROR, "No message given");
		return -1;
	}
#define max_len 2048
	if (len > max_len - 1){
		wpa_printf(MSG_ERROR, "The size of the message larger than the allowed size");
		return -1;
	}

	outgoing = os_malloc(sizeof(struct afq_mes));

	if (outgoing == NULL){
		wpa_printf(MSG_ERROR, "malloc failed");
		return -1;
	}

	outgoing->payload = os_malloc(len+1);
	os_snprintf(outgoing->payload, len+1, "%s", ptr);

	outgoing->next = NULL;
	outgoing->mid = hapd->msg_id++;
	outgoing->type = type;
	outgoing->paylen = len;

	wpa_printf(MSG_DEBUG, "outgoing dst " MACSTR, MAC2STR(addr));
	wpa_printf(MSG_DEBUG, "outgoint msg %s with length %d", outgoing->payload, outgoing->paylen);

	node = getNode(hapd, addr);

	if(node == NULL)
		node = addNode(hapd, addr);

	if(node == NULL)
		return -1;

	if (node->pending == NULL){
		node->pending = outgoing;
	}else{
		node->last->next = outgoing;
	}
	node->last = outgoing;

	if (is_broadcast_ether_addr(addr)){
		wpa_printf(MSG_DEBUG, "This is a broadcast message");
		send_new_broadcast_message(hapd, outgoing);
	}else{
		struct sta_info *sta = ap_get_sta(hapd, addr);
		if (sta)
			wpa_printf(MSG_DEBUG, "This is a message for a node in the BSS. Sending now");
		else
			wpa_printf(MSG_DEBUG, "This is a message for another node. Sending now");
		send_node_messages(hapd, node);
	}

	if(p2){
		u32 tout;
		p2++;
		p2 = os_strchr(p2, ':') + 1;
		tout = atoi(p2);
		wpa_printf(MSG_DEBUG, "Message timeout is %u seconds", tout);
		eloop_register_timeout(tout, 0, hapd_not_brct_timeout,
							   hapd, &outgoing->mid);

	}

	ret = os_snprintf(buf, end-buf, "MID: %u", outgoing->mid);
	if (ret < 0 || ret >= end-buf )
		return -1;

	return ret;
}

void hostapd_not_node_delete(struct hostapd_data *hapd, const u8 *addr){
	struct afq *node;
	struct afq *prev;
	struct afq_mes *mes, *m;
	char hwaddr[256];
	char cmd[32];
	int hwlen;
	int cmdlen;

	int loc = getLoc(addr);

	node = hapd->pend_list[loc];
	prev = NULL;

	while (node != NULL && os_memcmp(node->addr, addr, ETH_ALEN) != 0){
		prev = node;
		node = node->next;
	}

	if (node == NULL)
		return;

	if (prev == NULL){
		hapd->pend_list[loc] = node->next;
	}else{
		prev->next = node->next;
	}

	mes = node->pending;
	while (mes){
		m = mes->next;
		os_free(mes->payload);
		os_free(mes);
		mes = m;
	}

	hwlen = os_snprintf(hwaddr, 256, "Addr:" MACSTR, MAC2STR(addr));
	cmdlen = os_snprintf(cmd, 32, "%s", "OLDNODE");

	wpa_printf(MSG_DEBUG, "Informing the handling unit about the old node " MACSTR, MAC2STR(addr));
	hapd_not_iface_send(hapd, cmd, cmdlen, hwaddr, hwlen);

	wpa_printf(MSG_DEBUG, "Messages for " MACSTR " are deleted", MAC2STR(addr));

	wpa_printf(MSG_DEBUG, "Node " MACSTR " is deleted", MAC2STR(addr));
	os_free(node);

}

static void hapd_not_node_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct afq *node = timeout_ctx;
	struct sta_info *sta;

	wpa_printf(MSG_DEBUG, "No activity from the node " MACSTR, MAC2STR(node->addr));

	sta = ap_get_sta(hapd, node->addr);

	if (sta){
		wpa_printf(MSG_DEBUG, "Node " MACSTR " is within the BSS", MAC2STR(node->addr));
		return;
	}


	if (node){
		wpa_printf(MSG_DEBUG, "Deleting messages for node " MACSTR, MAC2STR(node->addr));
		hostapd_not_node_delete(hapd, node->addr);
	}
}



static void not_serv_rx_not_res(struct hostapd_data *hapd, const u8 *sa,
								const u8 *data, size_t len)
{
	const u8 *pos = data;
	const u8 *end = data + len;
	u32 mid;
	u16 slen;
	int buflen;
	char buf[4096];

	int cmdlen = 256;
	int res;

	char cmd[cmdlen];

	res = os_snprintf(cmd, cmdlen, "%s", "NOT_RESP");

	if (len < 6)
		return;

	mid = WPA_GET_LE32(pos);
	pos += 4;

	slen = WPA_GET_LE16(pos);
	pos += 2;

	wpa_printf(MSG_DEBUG, "The message comes from " MACSTR " with id %u and payload len %u", MAC2STR(sa), mid, slen);

	if (slen != len - 6){
		return;
	}

	if (end - pos != slen)
		return;


	buflen = os_snprintf(buf, sizeof(buf), "Addr:" MACSTR "MID:%u-", MAC2STR(sa), mid);
	if(slen + buflen > 4096)
		return;

	os_memcpy(buf+buflen, pos, slen);
	buf[buflen + slen] = '\0';

	wpa_printf(MSG_DEBUG, "Sending notification for handling");

	hapd_not_iface_send(hapd, cmd, res, buf, buflen+slen);

}


static void hostapd_recv_not_action_rx(void *ctx, const u8 *buf, size_t len, int freq)
{
	struct hostapd_data *hapd = ctx;
	const struct ieee80211_mgmt *mgmt;
	const u8 *sa, *data;

	mgmt = (const struct ieee80211_mgmt *) buf;
	if (len < IEEE80211_HDRLEN + 2)
		return;
	if (mgmt->u.action.category != WLAN_ACTION_PUBLIC &&
		mgmt->u.action.category != WLAN_ACTION_PROTECTED_DUAL)
		return;



	len -= IEEE80211_HDRLEN + 1;
	data = buf + IEEE80211_HDRLEN + 1;
	sa = mgmt->sa;

	wpa_printf(MSG_DEBUG, "Action frame is received from station " MACSTR, MAC2STR(sa));
/*NEWANDROID*/
	if(len > 2 && data[0] == WLAN_PA_GAS_INITIAL_REQ && data[1] == 255){
		len -= 2;
		data += 2;
		wpa_printf(MSG_DEBUG, "I received notification response disguised in the form of GAS req from " MACSTR, MAC2STR(sa));
	}
/*NEWANDROID*/


	if (data[0] == WLAN_PA_NOTIFICATION_RESP) {
		wpa_printf(MSG_DEBUG, "It is a response to a former notification");
		not_serv_rx_not_res(hapd, sa, data+1, len-1);
	}else if(data[0] == WLAN_PA_NOTIFICATION_REQ){
		wpa_printf(MSG_DEBUG, "It is a request for a notification");
		send_buffered_push_messages(hapd, sa, 0);
	}
}


static int start_not_connection(struct hostapd_data *hapd,
								struct sockaddr_un *from,
								socklen_t fromlen)
{
	struct not_ctrl_dst *dst;

	if (hapd->not_dst){
		return 1;
	}

	dst = os_zalloc(sizeof(*dst));
	if (dst==NULL)
		return -1;

	os_memcpy(&dst->addr, from, sizeof(struct sockaddr_un));
	dst->addrlen = fromlen;
	hapd->not_dst = dst;

	wpa_printf(MSG_DEBUG, "Notification unit started");

	return 0;

}

static int stop_not_connection(struct hostapd_data *hapd,
								struct sockaddr_un *from,
								socklen_t fromlen){

	struct not_ctrl_dst *dst;

	dst = hapd->not_dst;

	if (fromlen == dst->addrlen &&
	   os_memcmp(from->sun_path, dst->addr.sun_path,
				 fromlen - offsetof(struct sockaddr_un, sun_path))
	   == 0){
		hapd->not_dst = NULL;
		os_free(dst);
		wpa_printf(MSG_DEBUG, "Notification unit is stopped");
		return 0;
	}
	wpa_printf(MSG_DEBUG, "Notification unit can't be stopped");
	return -1;
}

int afn_set_timeout(struct hostapd_data *hapd, const char *buf)
{
	hapd->mtout = atoi(buf);
	wpa_printf(MSG_DEBUG, "Fast delivery timeout is set to %u", hapd->mtout);

	return 0;
}

static int afn_set_node_timeout(struct hostapd_data *hapd, const char *buf)
{
	hapd->ntout = atoi(buf);
	wpa_printf(MSG_DEBUG, "Node timeout is set to %u", hapd->ntout);

	return 0;
}

static int hapd_delete_brdcst_not(struct hostapd_data *hapd, u32 mid){
	struct afq *node;
	struct afq_mes *idx, *prev;

	node = hapd->pend_list[0];
	if (node){
		idx = node->pending;
		prev  = NULL;
		while (idx){
			if (idx->mid == mid){
				if (prev){
					prev->next = idx->next;
				}else{
					node->pending = idx->next;
				}
				os_free(idx->payload);
				os_free(idx);
				wpa_printf(MSG_DEBUG, "Broadcast %u is deleted", mid);

				return 0;
			}
			prev = idx;
			idx = idx->next;
		}
	}
	wpa_printf(MSG_DEBUG, "Broadcast %u is not found", mid);
	return -1;
}

int hapd_cmd_delete_brdcst_not(struct hostapd_data *hapd, char *cmd){
	u32 mid = atoi(cmd);
	return hapd_delete_brdcst_not(hapd, mid);
}

static int hostapd_cmd_delete_all_mes(struct hostapd_data *hapd, int end){
	struct afq *node, *n;
	struct afq_mes *mes, *m;
	int loc;

	wpa_printf(MSG_DEBUG, "Deleting all the messages");

	for(loc = 0; loc < STA_HASH_SIZE + 1; loc++){
		node = hapd->pend_list[loc];
		while(node){
			n = node->next;
			mes = node->pending;
			while (mes){
				m = mes->next;
				os_free(mes->payload);
				os_free(mes);
				mes = m;
			}
			node = n;
			if(end)
				os_free(n);
		}
	}

	return 0;

}

static int update_fast_not(struct hostapd_data *hapd, char *buf){
	int fn = atoi(buf);

	if(fn < 0 || fn > 1)
		return -1;

	hapd->fastnot = fn;
	return 0;
}


static void hapd_not_brct_timeout(void *eloop_ctx, void *timeout_ctx){
	struct hostapd_data *hapd = eloop_ctx;
	u32 mid = *((u32*)timeout_ctx);
	hapd_delete_brdcst_not(hapd, mid);
}


static void hostapd_not_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx){
	struct hostapd_data *hapd = eloop_ctx;
	char buf[4096];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
				   (struct sockaddr *) &from, &fromlen);

	if (res < 0) {
		perror("recvfrom(not_iface)");
		return;
	}

	wpa_printf(MSG_DEBUG, "A message from the notification unit is received");

	buf[res] = '\0';

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		wpa_printf(MSG_ERROR, "Can't generate response");
		sendto(sock, "FAIL\n", 5, 0, (struct sockaddr *) &from,
			   fromlen);
		return;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (os_strcmp(buf, "ATTACH") == 0){
		wpa_printf(MSG_DEBUG, "Start message is received");
		if (start_not_connection(hapd, &from, fromlen)){
			reply_len = -1;
		}
	} else if (os_strcmp(buf, "DETACH") == 0){
		wpa_printf(MSG_DEBUG, "Stop message is received");
		if (stop_not_connection(hapd, &from, fromlen)) {
			reply_len = -1;
		}
	} else if (os_strncmp(buf, "PUSH ", 5) == 0){
		wpa_printf(MSG_DEBUG, "New push is received");
		reply_len = afn_pending_append(hapd, buf + 5, reply, reply_size);
	} else if(os_strncmp(buf, "SETTIME ", 8) ==0) {
		wpa_printf(MSG_DEBUG, "The timeout message is received");
		if(afn_set_timeout(hapd, buf + 8)){
			reply_len = -1;
		}
	} else if (os_strncmp(buf, "DELETE ", 7) ==0){
		wpa_printf(MSG_DEBUG, "Delete message is received");
		if (hapd_cmd_delete_brdcst_not(hapd, buf + 7)){
			reply_len = -1;
		}
	} else if (os_strncmp(buf, "DELETEALL", 9) ==0){
		wpa_printf(MSG_DEBUG, "Requesting deleting all messages");
		if(hostapd_cmd_delete_all_mes(hapd, 0)){
			reply_len = -1;
		}
	} else if (os_strncmp(buf, "PING", 4) == 0){
		wpa_printf(MSG_DEBUG, "Ping is received");
		os_memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	} else if (os_strncmp(buf, "CHECK_FAST ", 11) == 0){
		if(update_fast_not(hapd, buf + 11)){
			reply_len = -1;
		}
	} else if (os_strncmp(buf, "SETNODETIME ", 12) == 0){
		if(afn_set_node_timeout(hapd, buf + 12))
			reply_len = -1;
	} else{
		reply_len = -1;
	}

	if (reply_len < 0){
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}

	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	os_free(reply);
}

static int not_iface_init(struct hostapd_data *hapd){
	struct sockaddr_un addr;
	int s = -1;
	char *fname = NULL;
	size_t len;
	struct afq *brdct;

	wpa_printf(MSG_DEBUG, "Starting Notification Interface");

	if (hapd->not_sock > -1){
		wpa_printf(MSG_ERROR, "Notification Interface already exists");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Path is %s",hapd->conf->ctrl_interface );

	len = os_strlen(hapd->conf->ctrl_interface) + 2 + os_strlen("notification");
	wpa_printf(MSG_DEBUG, "Socket len is %d", len);

	if (len-1 >= sizeof(addr.sun_path)){
		wpa_printf(MSG_ERROR, "Invalid length");
		goto fail;
	}

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));

#ifdef __FreeBSD__
	addr.sun_len = sizeof(addr);
#endif /* __FreeBSD__ */
	addr.sun_family = AF_UNIX;
	fname = os_malloc(len);
	if (fname == NULL){
		goto fail;

	}
	os_snprintf(fname, len, "%s/notification",
				hapd->conf->ctrl_interface);

	wpa_printf(MSG_DEBUG, "Socket name is %s", fname);
	fname[len-1] = '\0';
	os_strlcpy(addr.sun_path, fname, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "not_iface bind(PF_UNIX) failed: %s",
				   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			wpa_printf(MSG_ERROR, "not_iface exists, but does not"
					   " allow connections - assuming it was left"
					   "over from forced program termination");
			if (unlink(fname) < 0) {
				perror("unlink[not_iface]");
				wpa_printf(MSG_ERROR, "Could not unlink "
						   "existing not_iface socket '%s'",
						   fname);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
				0) {
				perror("hostapd-not-iface: bind(PF_UNIX)");
				goto fail;
			}
			wpa_printf(MSG_DEBUG, "Successfully replaced leftover "
					   "not_iface socket '%s'", fname);
		} else {
			wpa_printf(MSG_ERROR, "not_iface exists and seems to "
					   "be in use - cannot override it");
			wpa_printf(MSG_ERROR, "Delete '%s' manually if it is "
					   "not used anymore", fname);
			os_free(fname);
			fname = NULL;
			goto fail;
		}
	}

	if (chmod(fname, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[not_interface/ifname]");
		goto fail;
	}

	os_free(fname);
	hapd->not_sock = s;

	wpa_printf(MSG_DEBUG, "Socket initialized");

	eloop_register_read_sock(s, hostapd_not_iface_receive, hapd,
							 NULL);

	brdct = addNode(hapd, broadcast_ether_addr);
	if(brdct == NULL){
		goto fail;
	}

	return 0;

fail:
	if (s > 0)
		close(s);
	if (fname){
		unlink(fname);
		os_free(fname);
	}
	return -1;

}

void hostapd_deinit_notification(struct hostapd_data *hapd){
	wpa_printf(MSG_DEBUG, "Removing the notification unit");

	if (hapd->not_sock > -1){
		char *fname;
		size_t len;

		eloop_unregister_read_sock(hapd->not_sock);
		close(hapd->not_sock);
		hapd->not_sock = -1;

		len = os_strlen(hapd->conf->ctrl_interface) + 2 + os_strlen("notification");
		fname = os_malloc(len);
		os_snprintf(fname, len, "%s/notification",
					hapd->conf->ctrl_interface);

		if (fname)
			unlink(fname);
		os_free(fname);

		wpa_printf(MSG_DEBUG, "Notification socket is unlinked");

	}

	os_free(hapd->not_dst);

	hostapd_cmd_delete_all_mes(hapd, 1);
}


int hostapd_init_notification(struct hostapd_data *hapd){
	wpa_printf(MSG_DEBUG, "Initializing notification unit");

	/*Only use wlan0 for Wi-Push for now */
	if(os_strncmp(hapd->conf->iface, "wlan0", 5))
		return 0;

	hapd->public_action_cb = hostapd_recv_not_action_rx;
	hapd->public_action_cb_ctx = hapd;

	wpa_printf(MSG_DEBUG, "Action call back functions are registered");

	/*hostapd_register_probereq_cb(hapd, hostapd_not_probe_req_rx, hapd);
	wpa_printf(MSG_DEBUG, "Probe req call back function is registered");*/
	hapd->msg_id = 1;
	hapd->mtout = 1000;
	hapd->ntout = 500;
	hapd->fastnot = 1;
	os_memset(&hapd->pend_list, 0, sizeof(hapd->pend_list));

	return not_iface_init(hapd);
}

#endif /* CONFIG_ACTION_NOTIFICATION */
