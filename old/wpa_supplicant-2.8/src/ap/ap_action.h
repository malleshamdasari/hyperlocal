#ifndef AP_NOTIFICATION_H_
#define AP_NOTIFICATION_H_

int hostapd_init_notification(struct hostapd_data *hapd);
void hostapd_deinit_notification(struct hostapd_data *hapd);
int afn_pending_append(struct hostapd_data *hapd, const char *cmd, char *buf, size_t buflen);
int hapd_cmd_delete_not(struct hostapd_data *hapd, char *cmd);
void hostapd_not_node_delete(struct hostapd_data *hapd, const u8 *sa);
u8 * hostapd_eid_afn_indication(struct hostapd_data *hapd, u8 *eid);
int afn_set_timeout(struct hostapd_data *hapd, const char *buf);
int hapd_cmd_delete_brdcst_not(struct hostapd_data *hapd, char *cmd);
void send_buffered_push_messages(struct hostapd_data *hapd,
								 const u8 *addr, const u16 num);

#endif
