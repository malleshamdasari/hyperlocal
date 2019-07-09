/* 802.11 action frame notification handler 
 *
 * Research code. No reservations. Use on your own risk.
 *
 * This file contains routines useful for Wi-Push clients, most importantly
 * the socket communication with Android apps. It's implemented through
 * socket polling, which isn't exactly the most elegant way.
 *
 * Otto Waltari <otto.waltari@helsinki.fi>
 *
 */

#include "utils/includes.h"
#include <unistd.h>
#include <stddef.h>
//#include "errno.h"
#include <sys/un.h>
#include <fcntl.h>
#ifdef ANDROID
#include <cutils/sockets.h>
#endif /* ANDROID */

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "wpa_supplicant_i.h"
#include "offchannel.h"
#include "driver_i.h"
#include "config.h"
#include "bss.h"
#include "action_handler.h"

static const char AFN_SOCKNAME[] = "wpa_wipush";
static u16 check;

struct action_ctrl_dst{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int errors;
};

struct action_handle {
	struct wpa_supplicant *wpa_s;
	struct dl_list pending;
	struct action_ctrl_dst *dst;
	int fd;
	int sock;
 
};

struct action_pending {
	struct dl_list list;
	u8 addr[ETH_ALEN];
	u32 mid;
	int freq;
};


static void action_notification_req_dispatcher(struct wpa_supplicant *wpa_s, const u8 *addr, int freq);

static int start_not_connection(struct action_handle *act, struct sockaddr_un *from,
								socklen_t fromlen)
{
	struct action_ctrl_dst *dst;
	wpa_printf(MSG_DEBUG, "Connection request arrived");

	if (act->dst){
		wpa_printf(MSG_DEBUG, "Action interface already initialized");
		return 1;
	}

	dst = os_zalloc(sizeof(*dst));
	if (dst==NULL)
		return -1;

	os_memcpy(&dst->addr, from, sizeof(struct sockaddr_un));
	dst->addrlen = fromlen;
	act->dst = dst;
	wpa_printf(MSG_DEBUG, "Connection request accepted");

	return 0;
}

static int stop_not_connection(struct action_handle *act, struct sockaddr_un *from,
								socklen_t fromlen)
{
	struct action_ctrl_dst *dst;

	dst = act->dst;

	if (fromlen == dst->addrlen &&
		os_memcmp(from->sun_path, dst->addr.sun_path,
				fromlen - offsetof(struct sockaddr_un, sun_path))
		== 0){
		act->dst = NULL;
		os_free(dst);
		return 0;
	}
	return -1;
}

static struct action_pending *getPending(struct action_handle *act, const u8 *addr,  u32 mid){
	struct action_pending *q;
	wpa_printf(MSG_DEBUG, "Looking for the notification whose answer is pending");
	dl_list_for_each(q, &act->pending, struct action_pending, list) {
		wpa_printf(MSG_DEBUG, "This entry is from " MACSTR " with id %u", MAC2STR(q->addr), q->mid);
		if (os_memcmp(q->addr, addr, ETH_ALEN) == 0 &&
			q->mid == mid){
			wpa_printf(MSG_DEBUG, "Notification found");
			return q;
		}
	}
	return NULL;
}

static void delete_pending_action(struct action_pending *not){
	dl_list_del(&not->list);
	os_free(not);
}

static int action_notification_dispatcher(struct wpa_supplicant *wpa_s, struct action_pending *not, const char *payload, size_t paylen)
{
	int res;

	wpa_printf(MSG_DEBUG, "Preparing the answer to the notification");

	const u8 *dst = not->addr;
	const u8 *src = wpa_s->own_addr;
	const u8 *bssid = not->addr;

	struct wpabuf *buf;

	buf = wpabuf_alloc(AFN_BUF_MAX_LEN+5);
	if (buf == NULL){
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_GAS_INITIAL_REQ);
	wpabuf_put_u8(buf, 255);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_NOTIFICATION_RESP);
	wpabuf_put_le32(buf, not->mid);
	wpabuf_put_le16(buf, paylen);
	wpabuf_put_data(buf, payload, paylen);

	res =  offchannel_send_action(wpa_s, not->freq, dst, src, bssid, wpabuf_head(buf),  wpabuf_len(buf), 0, NULL, 0);
	wpa_printf(MSG_DEBUG, "  offchannel_send_action res = %d", res);
	offchannel_send_action_done(wpa_s);

	os_free(buf);
	delete_pending_action(not);

	return 0;
}

static int wpa_s_not_iface_process(struct wpa_supplicant *wpa_s, struct action_handle *act,
							const char *buf) 
{
	u8 addr[ETH_ALEN];
	int addr_len;
	u32 mid;
	const char *pos;

	struct action_pending *pending;

	if(buf == NULL){
		return -1;
	}

	addr_len = hwaddr_aton2(buf, addr);

	if(addr_len < 0)
		return -1;

	pos  = buf + addr_len;

	if(*pos++ != ' ')
		return -1;

	if(pos == NULL)
		return -1;

	mid = atoi(pos);

	pos = os_strchr(pos, ' ');

	if(pos == NULL || ++pos == NULL)
		return -1;

	pending = getPending(act, addr,  mid);

	if(pending == NULL)
		return -1;

	return action_notification_dispatcher(wpa_s, pending, pos, os_strlen(pos));
}

static void wpa_s_not_iface_recv(int sock, void *eloop_ctx, void *sock_ctx){
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct action_handle *act = sock_ctx;
	char buf[4096];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply = NULL;//, *reply_buf = NULL;
	int reply_len = 0;

	wpa_printf(MSG_DEBUG, "Message received from the notification unit");

	res =  recvfrom(sock, buf, sizeof(buf) - 1, 0,
					(struct sockaddr *) &from, &fromlen);


	if (res < 0) {
		wpa_printf(MSG_DEBUG, "recvfrom(ctrl_iface): %s",
				strerror(errno));
		return;
	}
	buf[res] = '\0';

	reply = os_malloc(5);

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if(os_strcmp(buf, "ATTACH") == 0){
		wpa_printf(MSG_DEBUG, "Attach request received");
		if(start_not_connection(act, &from, fromlen)){
			reply_len = -1;
		}
	}else if(os_strcmp(buf , "DETACH") == 0){
		wpa_printf(MSG_DEBUG, "Detach request received");
		if(stop_not_connection(act, &from, fromlen)){
			reply_len = -1;
		}
	} else if(os_strncmp(buf, "ACTION ", 7) == 0){
		wpa_printf(MSG_DEBUG, "Action request received with %s", buf+7);
		if(wpa_s_not_iface_process(wpa_s, act, buf+7)){
			reply_len = -1;
		}
	}else if (os_strcmp(buf, "PING") == 0) {
		os_memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	}else{
		wpa_printf(MSG_DEBUG, "Message %s not defined", buf);
		reply_len = -1;
	}

	if (reply_len < 0){
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}

	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	os_free(reply);

}


static int wpas_not_open_sock(struct wpa_supplicant *wpa_s, struct action_handle *act)
{
	struct sockaddr_un addr;
	int flags;
	char *buf = NULL;
	char *pbuf, *dir = NULL;
	size_t len;
	int res;

	wpa_printf(MSG_DEBUG, "Starting Notification Interface");

	if(act->sock > -1){
		wpa_printf(MSG_DEBUG, "Notification Interface already exists");
		return 0;
	}

#ifdef ANDROID
	act->sock = android_get_control_socket(AFN_SOCKNAME);
	if (act->sock >= 0)
		goto havesock;
#endif /*ANDROID*/

	if (wpa_s->conf->ctrl_interface == NULL)
		goto fail;

	pbuf = os_strdup(wpa_s->conf->ctrl_interface);
	if(pbuf == NULL)
		goto fail;

	if (os_strncmp(pbuf, "DIR=", 4) == 0) {
		char *gid_str;
		dir = pbuf + 4;
		gid_str = os_strstr(dir, " GROUP=");
		if (gid_str)
			*gid_str = '\0';
	} else
		dir = pbuf;

	len = os_strlen(dir)+2+os_strlen(AFN_SOCKNAME);
	buf = os_malloc(len);
	if (buf == NULL) {
		os_free(pbuf);
		return -1;
	}

	res = os_snprintf(buf, len, "%s/%s", dir, AFN_SOCKNAME);
	if (res < 0 || (size_t) res >= len) {
		os_free(pbuf);
		os_free(buf);
		goto fail;
	}

	os_free(pbuf);
	wpa_printf(MSG_DEBUG, "Name of the socket is %s", buf);

	act->sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if(act->sock < 0){
		wpa_printf(MSG_ERROR, "socket(PF_UNIX): %s", strerror(errno));
		goto fail;
	}
	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	os_strlcpy(addr.sun_path, buf, sizeof(addr.sun_path));

	if(bind(act->sock,  (struct sockaddr *) &addr, sizeof(addr)) < 0){
		wpa_printf(MSG_ERROR, "not_iface bind(PF_UNIX) failed: %s",
				strerror(errno));
		if (connect(act->sock, (struct sockaddr *) &addr,
					sizeof(addr)) < 0) {
			wpa_printf(MSG_ERROR, "not_iface exists, but does not"
					" allow connections - assuming it was left"
					"over from forced program termination");
			if (unlink(buf) < 0) {
				wpa_printf(MSG_ERROR,
						"Could not unlink existing ctrl_iface socket '%s': %s",
						buf, strerror(errno));
				goto fail;
			}
			if (bind(act->sock, (struct sockaddr *) &addr,
					 sizeof(addr)) < 0) {
				wpa_printf(MSG_ERROR, "supp-not-iface-init: bind(PF_UNIX): %s",
						strerror(errno));
				goto fail;
			}
			wpa_printf(MSG_ERROR, "Successfully replaced leftover "
					"ctrl_iface socket '%s'", buf);
		} else {
			wpa_printf(MSG_ERROR, "ctrl_iface exists and seems to "
					"be in use - cannot override it");
			wpa_printf(MSG_ERROR, "Delete '%s' manually if it is "
					"not used anymore", buf);
			os_free(buf);
			buf = NULL;
			goto fail;
		}
	}
	os_free(buf);
	wpa_printf(MSG_DEBUG, "Socket binded");

#ifdef ANDROID
havesock:
#endif /*ANDROID*/

	flags = fcntl(act->sock, F_GETFL);
	if(flags >= 0){
		flags |= O_NONBLOCK;
		if (fcntl(act->sock, F_SETFL, flags) < 0) {
			wpa_printf(MSG_ERROR, "fcntl(ctrl, O_NONBLOCK): %s",
				strerror(errno));
			/* Not fatal, continue on.*/
		}
	}

	eloop_register_read_sock(act->sock, wpa_s_not_iface_recv,
				 wpa_s, act);

	return 0;

fail:
	if(act->sock >= 0){
		close(act->sock);
		act->sock = -1;
	}

	if(buf){
		unlink(buf);
		os_free(buf);
	}
	return -1;
}

int action_init(struct wpa_supplicant *wpa_s) {
	struct action_handle *act;

	wpa_printf(MSG_DEBUG, "initializing action listener for %s", wpa_s->ifname);
	/* This is a quick hack. We want to enable this only for the primary wlan interface.
	 By default on an Android device with wpa_supplicant compiled with eg. P2P enabled
	 a virtual p2p0 interface is generated. */

	if (memcmp(wpa_s->ifname, "wlan0", 5)) {
		wpa_printf(MSG_ERROR, "   -> not wlan0, no action");
		return 0;
	}

	act = os_zalloc(sizeof(struct action_handle));

	if (act == NULL)
		return -1;

	wpa_s->act = act;
	act->wpa_s = wpa_s;
	dl_list_init(&act->pending);
	check = 0;

	act->sock = -1;
	wpa_printf(MSG_DEBUG, "initializing the socket");

	if (wpas_not_open_sock(wpa_s, act) < 0) {
		os_free(act);
		return -1;
	}

	return 0;
}

void action_notification_add_indication(struct wpabuf *buf, int pps_mo_id) {
	/* This is called from scan.c while preparing probe requests. */

	wpa_printf(MSG_DEBUG, "Adding notification indicator to the probe request");

	wpabuf_put_u8(buf, WLAN_EID_NOT_INDICATOR);
	//wpabuf_put_u8(buf, 0);
	wpabuf_put_u8(buf, 2);
	wpabuf_put_le16(buf, check);

}

void wpa_action_notify_presence(struct wpa_supplicant *wpa_s, int type){
	struct action_handle *act = wpa_s->act;
	struct action_ctrl_dst *dst;
	struct msghdr msg;
	struct iovec io[2];

	char buf[64];
	int len;

	char buf2[64];
	int len2;

	dst = act->dst;

	if(act->sock < 0 || dst == NULL)
		return;

	len = os_snprintf(buf, 63, "ANNOUNCE %d", type);
	io[0].iov_base = buf;
	io[0].iov_len = len;

	len2 = os_snprintf(buf2, 63, "id: %u", check++);
	io[1].iov_base = buf2;
	io[1].iov_len = len2;

	os_memset(&msg, 0, sizeof(msg));
	//msg.msg_iov = &io;
	msg.msg_iov = io;
	msg.msg_iovlen = 2;
	msg.msg_name = &dst->addr;
	msg.msg_namelen = dst->addrlen;

	if (sendmsg(act->sock, &msg, 0) < 0){
		int _errno = errno;
		wpa_printf(MSG_ERROR, "NOTIFICATION IFACE error: %d - %s", errno, strerror(errno));
		dst->errors++;
		if (dst->errors > 10 || _errno == ENOENT){
			stop_not_connection(act, &dst->addr, dst->addrlen);
		}
	}else{
		wpa_printf(MSG_DEBUG, "Notification sent upstream");
		dst->errors = 0;
	}
}

static int send_notification_upstream(struct action_handle *act, u8 type, 
						const u8 *sa, u32 mid, const u8 *pos, size_t slen)
{
	struct iovec io[4];
	//int idx = 0 ;
	struct msghdr msg;
	int len1, len2;
	struct action_ctrl_dst *dst;
	int ret;

	wpa_printf(MSG_DEBUG, "Sending received notification for handling");

	char buf1[128];
	char buf2[128];

	char buf3[128];
	int len3;
	u16 num;

	len1 = os_snprintf(buf1, 128, "NOT:Type:%u-", type - WLAN_PA_NO_RESP);
	len2 = os_snprintf(buf2, 128, "Addr:" MACSTR "-MID:%u-", MAC2STR(sa), mid);

	wpa_printf(MSG_DEBUG, "The message is %s %s %s", buf1, buf2, (char *)pos);

	dst = act->dst;
	if(act->sock < 0 || dst == NULL)
		return -1;

	io[0].iov_base = buf1;
	io[0].iov_len = len1;

	io[1].iov_base = buf2;
	io[1].iov_len = len2;

	io[2].iov_base = (char *) pos;
	io[2].iov_len = slen;

	num = WPA_GET_LE16(pos+slen);
	len3 = os_snprintf(buf3, 128, "CheckId:%u",num);
	io[3].iov_base = buf3;
	io[3].iov_len = len3;

	os_memset(&msg, 0, sizeof(msg));
	msg.msg_iov = io;
	msg.msg_iovlen = 4;
	msg.msg_name = &dst->addr;
	msg.msg_namelen = dst->addrlen;

	if (sendmsg(act->sock, &msg, 0) < 0){
		int _errno = errno;
		wpa_printf(MSG_ERROR, "NOTIFICATION IFACE error: %d - %s", errno, strerror(errno));
		dst->errors++;
		if (dst->errors > 10 || _errno == ENOENT){
			stop_not_connection(act, &dst->addr, dst->addrlen);
		}
		ret = -1;
	}else{
		wpa_printf(MSG_DEBUG, "Notification sent upstream");
		dst->errors = 0;
		ret = 0;
	}

	return ret;
}

static int deliver_notification(struct wpa_supplicant *wpa_s, struct action_handle *act, const u8 *sa, const u8 *payload, int freq)
{
	if(act == NULL)
		return -1;

	u8 type;
	u32 mid;
	u16 slen;
	const u8 *pos = payload;

	wpa_printf(MSG_DEBUG, "Processing the received notification");

	type = *pos++;

	mid = WPA_GET_LE32(pos);
	pos += 4;

	slen = WPA_GET_LE16(pos);

	if(slen < 1)
		return -1;

	pos += 2;

	if(type == WLAN_PA_WAIT_RESP){
		struct action_pending *not;
		wpa_printf(MSG_DEBUG, "Notification requires an answer");

		/*NOTIFICATION ALREADY RECEIVED*/
		not = getPending(act, sa, mid);
		if(not != NULL){
			wpa_printf(MSG_DEBUG, "This message from " MACSTR " with id %u is already received", MAC2STR(sa), mid);
			return 0;
		}

		wpa_printf(MSG_DEBUG, "Generating an entry for the notification");

		not = os_malloc(sizeof(struct action_pending));
		os_memcpy(not->addr, sa, ETH_ALEN);
		not->mid = mid;
		not->freq = freq;
		dl_list_add(&act->pending, &not->list);
	}

	return send_notification_upstream(act, type, sa, mid, pos, slen);

}

static void wpa_action_req_not_ind(void *eloop_ctx, void *timeout_ctx){
	struct wpa_supplicant *wpa_s = eloop_ctx;
	u8 *pos = timeout_ctx;
	u8 addr[ETH_ALEN];
	int freq;

	os_memcpy(addr, pos, ETH_ALEN);
	os_memcpy(&freq, pos + ETH_ALEN, sizeof(freq));
	wpa_printf(MSG_DEBUG, "Sending AF to " MACSTR " at %d MHz", MAC2STR(addr), freq);

	action_notification_req_dispatcher(wpa_s, addr, freq);
	wpa_action_notify_presence(wpa_s, 2);
	os_free(pos);

}

static int schedule_req(struct wpa_supplicant *wpa_s, const u8 *sa, const u8 *payload, int freq)
{
	u16 tout = WPA_GET_LE16(payload);
	size_t mylen = sizeof(freq) + ETH_ALEN;
	u8 *buf = os_malloc(mylen);
	if(buf == NULL)
		return -1;

	wpa_printf(MSG_DEBUG, "Scheduling a action frame to signal to the AP that we are up");
	wpa_printf(MSG_DEBUG, "The message will be sent in %u ms at freq %d", tout, freq);

	os_memcpy(buf, sa, ETH_ALEN);
	os_memcpy(buf + ETH_ALEN, &freq, sizeof(freq));

	eloop_register_timeout(tout / 1000, 1000*(tout % 1000), wpa_action_req_not_ind,
						wpa_s, buf);

	return 0;
}


int action_rx(struct wpa_supplicant *wpa_s, const u8 *da, const u8 *sa,
			const u8 *bssid, u8 categ, const u8 *data, size_t len,
			int freq)
{
	/* This is called in events.c on incoming public action frames. */
	struct action_handle *act = wpa_s->act;
	u8 stype;
	int ret;  
	const u8 *pos;

	wpa_printf(MSG_DEBUG, "Action frame is received from " MACSTR, MAC2STR(sa));

	pos = data;

	if(pos == NULL)
		return -1;

/*NEWANDROID*/
	if(*pos++ == WLAN_PA_GAS_INITIAL_RESP)
		if(*pos == 255){
			pos++;
			wpa_printf(MSG_ERROR, "I received notification disguised in the form of GAS resp from " MACSTR, MAC2STR(sa));
		}

/*NEWANDROID*/

	stype = *pos++;

	wpa_printf(MSG_DEBUG, "Action frame type is %u, length is %zu", stype, len);

	switch(stype){
		case WLAN_PA_NOTIFICATION:
			wpa_printf(MSG_DEBUG, "Notification is received");
			if(len < 10)
				ret = -1;
			else
				ret = deliver_notification(wpa_s, act, sa, pos, freq);
			break;
		case WLAN_PA_NOTIFICATION_IND:
			wpa_printf(MSG_DEBUG, "Notification indicator is received");
			if(len < 3)
				ret = -1;
			else{
				ret = schedule_req(wpa_s, sa, pos, freq);
			}
			break;
		default:
			ret = -1;
	}
	return ret;
}

static void action_notification_req_dispatcher(struct wpa_supplicant *wpa_s,
									const u8 *addr, int freq)
{
	int res;
	const u8 *src = wpa_s->own_addr;
	struct wpabuf *buf;

	buf = wpabuf_alloc(2);
	if (buf == NULL){
		return;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_GAS_INITIAL_REQ);
	wpabuf_put_u8(buf, 255);
/*NEWANDROID*/
	wpabuf_put_u8(buf, WLAN_PA_NOTIFICATION_REQ);

	wpa_printf(MSG_DEBUG, "Notification request is being sent at frequency %d to " MACSTR, freq, MAC2STR(addr));

	res =  offchannel_send_action(wpa_s, freq, addr, src, addr, wpabuf_head(buf), wpabuf_len(buf), 0, NULL, 0);
	wpa_printf(MSG_DEBUG, "  offchannel_send_action res = %d", res);

	os_free(buf);
	wpa_printf(MSG_DEBUG, "Notification request is sent");

}
 
void wpa_action_req_not(void *eloop_ctx, void *timeout_ctx){
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_bss *bss = timeout_ctx;

	wpa_printf(MSG_DEBUG, "Notification indicator from probe response");
	action_notification_req_dispatcher(wpa_s, bss->bssid, bss->freq);
	wpa_action_notify_presence(wpa_s, 1);
}

void wpa_action_cleanup(struct wpa_supplicant *wpa_s){
	char *buf = NULL;
	char *pbuf, *dir = NULL;
	size_t len;
	int res;
	struct action_handle *act = wpa_s->act;
	struct action_pending *q, *qold = NULL;

	wpa_printf(MSG_DEBUG, "Terminating notification unit");

	if(act==NULL){
		wpa_printf(MSG_ERROR, "No notification unit");
		return;
	}

	eloop_unregister_read_sock(act->sock);
	close(act->sock);
	act->sock = -1;

	if(wpa_s->conf->ctrl_interface != NULL){
		pbuf = os_strdup(wpa_s->conf->ctrl_interface);

		if (os_strncmp(pbuf, "DIR=", 4) == 0) {
			char *gid_str;
			dir = pbuf + 4;
			gid_str = os_strstr(dir, " GROUP=");
			if (gid_str)
				*gid_str = '\0';
		} else
			dir = pbuf;

		len = os_strlen(dir)+2+os_strlen(AFN_SOCKNAME);
		buf = os_malloc(len);
		if (buf == NULL) {
			os_free(pbuf);
			return;
		}

		res = os_snprintf(buf, len, "%s/%s", dir, AFN_SOCKNAME);
		if (res < 0 || (size_t) res >= len) {
			os_free(pbuf);
			os_free(buf);
			return;
		}

		os_free(pbuf);
		if(buf){
			unlink(buf);
			os_free(buf);
		}
	}

	wpa_printf(MSG_DEBUG, "Socket is unlinked");

	dl_list_for_each(q, &act->pending, struct action_pending, list){
		if(qold!=NULL)
			os_free(qold);
		qold=q;
	}

	if(qold!=NULL)
		os_free(qold);

	os_free(act->dst);
	os_free(act);
	wpa_printf(MSG_DEBUG, "Everything is cleaned up");

}

