#include "includes.h"

#include <time.h>
#include <fcntl.h>

#include "common/wpa_ctrl.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "utils/list.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"
#ifdef ANDROID
#include <cutils/properties.h>
#endif /* ANDROID */

#include <netdb.h>
#include "common/cli.h"

static struct wpa_ctrl *not_conn;

#ifndef CONFIG_CTRL_IFACE_DIR
#define CONFIG_CTRL_IFACE_DIR "/var/run/hostapd"
#endif /* CONFIG_CTRL_IFACE_DIR */
static const char *ctrl_iface_dir = CONFIG_CTRL_IFACE_DIR;
static const char *client_socket_dir = NULL;
static const char SCKNAME[] = "notification";
static int ping_interval = 2;
static int not_attached = 0;
static int interactive = 0;
static int broadcast_test = 0;
static int dynamic_test = 0;
static int last_mid = 0;
static int count = 0;
static const char *action_file = NULL;
static char *ctrl_ifname = NULL;
static int event_handler_registered = 0;
static int hostapd_cli_attached = 0;
static DEFINE_DL_LIST(stations); /* struct cli_txt_entry */

static void not_recv_pending(struct wpa_ctrl *ctrl);
static void hostapd_cli_receive(int sock, void *eloop_ctx, void *sock_ctx);
static void not_close_connection(void);

struct per_not{
	int num;
	int count;
	u32 period;
	char *mes;
	struct per_not *next;
	struct per_not *prev;
};

struct per_not *pn_;

static void remove_all_chars(char* str, char c) {
	char *pr = str, *pw = str;
	while (*pr) {
		*pw = *pr++;
		pw += (*pw != c);
	}
	*pw = '\0';
}

int *pystub_sockfd;
#define NOT_PYSTUB_PORT_NO 9998
static int not_connect_pystub()
{
	int sockfd, portno, n;
	
	struct sockaddr_in serv_addr;
	struct hostent *server;
	
	char buffer[256];

	portno = NOT_PYSTUB_PORT_NO;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0){
		printf("ERROR opening socket for pystub\n");
		return -1;
	}
	server = gethostbyname("localhost");
	if (server == NULL){
		printf("ERROR, no such host\n");
		return -1;
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
	     (char *)&serv_addr.sin_addr.s_addr,
	     server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0){ 
		printf("ERROR connecting the pystub\n");
		return -1;
	}
	
	pystub_sockfd = &sockfd;
	return 0;
}

static int not_disconnect_pystub()
{
	close(*pystub_sockfd);
}

static void register_event_handler(struct wpa_ctrl *ctrl)
{
	if (!not_conn)
		return;
	if (interactive) {
		event_handler_registered =
			!eloop_register_read_sock(wpa_ctrl_get_fd(ctrl),
						  hostapd_cli_receive,
						  NULL, NULL);
	}
}


static void unregister_event_handler(struct wpa_ctrl *ctrl)
{
	if (!not_conn)
		return;
	if (interactive && event_handler_registered) {
		eloop_unregister_read_sock(wpa_ctrl_get_fd(ctrl));
		event_handler_registered = 0;
	}
}


static struct wpa_ctrl * hostapd_cli_open_connection(const char *ifname)
{
#ifndef CONFIG_CTRL_IFACE_UDP
	char *cfile;
	int flen;
#endif /* !CONFIG_CTRL_IFACE_UDP */

	if (ifname == NULL)
		return NULL;

#ifdef CONFIG_CTRL_IFACE_UDP
	not_conn = wpa_ctrl_open(ifname);
	return not_conn;
#else /* CONFIG_CTRL_IFACE_UDP */
	flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2;
	cfile = malloc(flen);
	if (cfile == NULL)
		return NULL;
	snprintf(cfile, flen, "%s/%s", ctrl_iface_dir, ifname);

	if (client_socket_dir && client_socket_dir[0] &&
	    access(client_socket_dir, F_OK) < 0) {
		perror(client_socket_dir);
		free(cfile);
		return NULL;
	}

	not_conn = wpa_ctrl_open2(cfile, client_socket_dir);
	free(cfile);
	return not_conn;
#endif /* CONFIG_CTRL_IFACE_UDP */
}


static void hostapd_cli_close_connection(void)
{
	if (not_conn == NULL)
		return;

	unregister_event_handler(not_conn);
	if (hostapd_cli_attached) {
		wpa_ctrl_detach(not_conn);
		hostapd_cli_attached = 0;
	}
	wpa_ctrl_close(not_conn);
	not_conn = NULL;
}


static int hostapd_cli_reconnect(const char *ifname)
{
	char *next_ctrl_ifname;

	hostapd_cli_close_connection();

	if (!ifname)
		return -1;

	next_ctrl_ifname = os_strdup(ifname);
	os_free(ctrl_ifname);
	ctrl_ifname = next_ctrl_ifname;
	if (!ctrl_ifname)
		return -1;

	not_conn = hostapd_cli_open_connection(ctrl_ifname);
	if (!not_conn)
		return -1;
	if (!interactive && !action_file)
		return 0;
	if (wpa_ctrl_attach(not_conn) == 0) {
		hostapd_cli_attached = 1;
		register_event_handler(not_conn);
		update_stations(not_conn);
	} else {
		printf("Warning: Failed to attach to hostapd.\n");
	}
	return 0;
}



static void command_status(int status){

	time_t sec = time ( NULL );

	printf("%ld: ", sec);

	if(status){
		printf("Command succeeded");
	}else{
		printf("Command failed");
	}

	printf("\n");
}

static void register_new_message(char *buf, size_t len){
	time_t sec;
	char out[1024];
	int loc;
	char *pos, *end;

	if(len <= 0){
		command_status(0);
		return;
	}

	sec = time (NULL);

	pos = out;
	end = pos + sizeof(out);

	loc = os_snprintf(pos, end - pos, "%ld: New message registered with id ", sec);
	pos += loc;

	os_snprintf(pos, end - pos, "%s", buf);

	last_mid = atoi(buf);

	printf("%s\n", out);
}

static void not_msg_cb(char *msg, size_t len)
{
	char *pos = msg;
	if (os_strncmp(pos, "MID: ", 5) == 0){
		register_new_message(pos +4 , len - 4);
	} else if (os_strncmp(pos, "FAIL", 4) == 0){
		command_status(0);
	} else if (os_strncmp(pos, "OK", 2) == 0){
		command_status(1);
	}else{
		printf("Unknown message\n");
	}

	printf("%s\n", msg);
}

static int _not_command(struct wpa_ctrl *ctrl, char *cmd, int print)
{
	char buf[4096];
	size_t len;
	int ret;
	time_t sec = time (NULL);

	if (not_conn == NULL) {
		printf("Not connected to hostapd - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
						   not_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		printf("%ld\t%s\n", sec, buf);
	}
	return 0;
}


static inline int not_command(struct wpa_ctrl *ctrl, char *cmd)
{
	return _not_command(ctrl, cmd, 1);
}

static int not_broadcast(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];
	char *pos, *end;
	int res;

	if(argc < 2 || argc > 3){
		printf("Invalid broadcast notification command\n");
		return -1;
	}

	if(broadcast_test || dynamic_test){
		printf("There is already a %s test going on. No new messages are accepted\n", broadcast_test ? "broadcast" : "dynamic");
		return -1;
	}

	if( os_strcmp(argv[0], "0") == 0 && os_strcmp(argv[0], "1") == 0 ){
		printf("Invalid response request, should be either 0 or 1. We have %s\n", argv[0]);
		return -1;
	}

	pos = cmd;
	end = pos + sizeof(cmd);


	res = os_snprintf(pos, end - pos, "PUSH ff:ff:ff:ff:ff:ff %s %s", argv[0], argv[1]);
	if (res < 0 || res >= end - pos - 1) {
		printf("Too long PUSH command.\n");
		return -1;
	}

	if(argc == 3){
		pos += res;
		res = os_snprintf(pos, end - pos, " :ENDNOT: %s", argv[2]);

		if (res < 0 || res >= end - pos - 1) {
			printf("Too long PUSH command.\n");
			return -1;
		}
	}

	remove_all_chars(cmd, '"');
	return not_command(ctrl, cmd);
	
}

static int not_enable_fast_delivery(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	return not_command(ctrl, "CHECK_FAST 1");
}

static int not_disable_fast_delivery(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	return not_command(ctrl, "CHECK_FAST 0");
}

static int not_new(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];
	char *pos, *end;
	int res, i;
	
	if (argc < 3) {
		printf("Invalid 'notification' command - three arguments "
			   "(STA addr, whether it requires a response and notification message) are needed\n");
		return -1;
	}

	if(broadcast_test || dynamic_test){
		printf("There is already a %s test going on. No new messages are accepted\n", broadcast_test ? "broadcast" : "dynamic");
		return -1;
	}
	
	pos = cmd;
	end = pos + sizeof(cmd);
	
	res = os_snprintf(pos, end-pos, "PUSH");
	
	for(i = 0; i < 3; i++){
		pos += res;
		res = os_snprintf(pos, end-pos, " %s", argv[i]);
		if (res < 0 || res >= end-pos) {
			printf("Too long PUSH command.\n");
			return -1;
		}
	}
	
	if(argc > 3 && os_strncmp(argv[0], "ff:ff:ff:ff:ff:ff", 17)==0){
		pos +=res;
		res = os_snprintf(pos, end-pos, " :ENDNOT:%s", argv[3]);
		if (res < 0 || res >= end-pos) {
			printf("Too long PUSH command.\n");
			return -1;
		}
	}

	remove_all_chars(cmd, '"');
	return not_command(ctrl, cmd);
}

static int not_push_cb(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	not_command(ctrl, argv[0]);
}

static void send_periodic_not(void *eloop_ctx, void *timeout_ctx){
	struct per_not *nt = timeout_ctx;
	struct wpa_ctrl *ctrl = eloop_ctx;
	
	if(nt->count < nt->num){
		nt->count++;
		not_command(ctrl, nt->mes);
		eloop_register_timeout(nt->period/1000, 1000 * (nt->period%1000), send_periodic_not, ctrl, nt);
	}else{
		os_free(nt->mes);
		if(nt->prev)
			nt->prev->next = nt->next;
		if(nt->next)
			nt->next->prev = nt->prev;
		os_free(nt);
	}
}

static int not_periodic(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];
	u32 period;
	char *pos, *end;
	int res, i;
	int num;
	struct per_not *nt;

	if (argc < 5) {
		printf("Invalid 'periodic notification' command - five arguments "
			   "(period,number, STA addr, whether it requires a response and notification message) are needed\n");
		return -1;
	}

	if(broadcast_test || dynamic_test){
		printf("There is already a %s test going on. No new messages are accepted\n", broadcast_test ? "broadcast" : "dynamic");
		return -1;
	}

	period = atoi(argv[0]);
	num = atoi(argv[1]);

	pos = cmd;
	end = pos + sizeof(cmd);

	res = os_snprintf(pos, end-pos, "PUSH");

	for(i = 2; i < 5; i++){
		pos += res;
		res = os_snprintf(pos, end-pos, " %s", argv[i]);
		if (res < 0 || res >= end-pos) {
			printf("Too long PUSH command.\n");
			return -1;
		}
	}

	if(argc > 5 && os_strncmp(argv[2], "ff:ff:ff:ff:ff:ff", 17)==0){
		pos +=res;
		res = os_snprintf(pos, end-pos, " :ENDNOT:%s", argv[5]);
		if (res < 0 || res >= end-pos) {
			printf("Too long PUSH command.\n");
			return -1;
		}
	}

	remove_all_chars(cmd, '"');

	nt = os_malloc(sizeof(struct per_not));
	nt->count = 0;
	nt->num = num;
	nt->period = period;
	nt->mes = os_strdup(cmd);
	nt->next = pn_;
	nt->prev = NULL;
	if(pn_)
		pn_->prev = nt;
	pn_ = nt;

	eloop_register_timeout(0, 0, send_periodic_not, ctrl, nt);

	return 0;
}

static int fast_periodic(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];
	u32 period;
	int res, i;
	long num;
	struct per_not *nt;
	int tout;

	if (argc < 3) {
		printf("Invalid 'periodic notification' command - five arguments "
			   "(period,number, STA addr, whether it requires a response and notification message) are needed\n");
		return -1;
	}

	if(broadcast_test || dynamic_test){
		printf("There is already a %s test going on. No new messages are accepted\n", broadcast_test ? "broadcast" : "dynamic");
		return -1;
	}

	period = atoi(argv[0]);
	num = atoi(argv[1]);
	tout = atoi(argv[3])/1000 + 1;


	res = os_snprintf(cmd, sizeof(cmd), "PUSH ff:ff:ff:ff:ff:ff 0 %s :ENDNOT:%d", argv[2], tout);

	if (res < 0 || res >= sizeof(cmd)) {
		printf("Too long PUSH command.\n");
		return -1;
	}

	remove_all_chars(cmd, '"');


	nt = os_malloc(sizeof(struct per_not));
	nt->count = 0;
	nt->num = num;
	nt->period = period;
	nt->mes = os_strdup(cmd);
	nt->next = pn_;
	nt->prev = NULL;

	if(pn_)
		pn_->prev = nt;
	pn_ = nt;

	eloop_register_timeout(0, 0, send_periodic_not, ctrl, nt);

}

static int not_cmd_quit(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	not_close_connection();
	if(interactive){
		eloop_terminate();
	}
	return 0;
}

static int delete_msg(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];

	if(argc < 1){
		printf("We should know the message id to delete\n");
		return -1;
	}

	os_snprintf(cmd, 2048, "DELETE %s", argv[0]);
	return not_command(ctrl, cmd);

}

static int delete_all_msg(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[] = "DELETEALL";

	struct per_not *p = pn_;

	while(p){
		pn_= p->next;

		eloop_cancel_timeout(send_periodic_not, ctrl, p);

		os_free(p->mes);
		os_free(p);

		p = pn_;
	}

	return not_command(ctrl, cmd);

}

static int test_broadcast(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];

	if(broadcast_test){
		broadcast_test = 0;
		return os_snprintf(cmd, 2048, "DELETE %u", last_mid);
	}

	os_snprintf(cmd, 2047, "PUSH ff:ff:ff:ff:ff:ff 0 \"This is a broadcast message\"");
	broadcast_test = 1;

	return not_command(ctrl, cmd);
}

static int test_dynamic(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	if(broadcast_test){
		printf("Broadcast test is already in action. Do this later\n");
		goto finish;
	}

	if(dynamic_test){
		dynamic_test = 0;
		count = 0;
	}else
		dynamic_test = 1;

finish:
	return 0;
}


static int set_node_expire(struct wpa_ctrl *ctrl, int argc, char *argv[]){
	char cmd[2048];
	int res = 0;

	if(argc < 1){
		printf("Please enter the node expiry time in seconds\n");
		return -1;
	}

	res= os_snprintf(cmd, 2047, "SETNODETIME %s", argv[0]);
	if(res < 0 || res > 2047){
		return -1;
	}

	printf("Node expiry timeout is changed to %s\n", argv[0]);

	return not_command(ctrl, cmd);
}

struct not_cmd {
	const char *cmd;
	int (*handler)(struct wpa_ctrl *ctrl, int argc, char *argv[]);
};

static struct not_cmd not_commands[] = {
	{ "broadcast" , not_broadcast },
	{ "enablefast" , not_enable_fast_delivery },
	{ "disablefast" , not_disable_fast_delivery },
	{ "push" , not_push_cb },
	{ "periodic" , not_periodic },
	{ "fastper" , fast_periodic },
	{ "delmes", delete_msg },
	{ "delallmes", delete_all_msg },
	{ "quit", not_cmd_quit },
	{ "btest" , test_broadcast },
	{ "dtest" , test_dynamic },
	{ "expirenode" , set_node_expire },
	{ NULL, NULL }
};

// Handle the commands received from Pystub
static void not_cmd_handler(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	struct not_cmd *cmd, *match = NULL;
	int count;
	
	count = 0;
	cmd = not_commands;
	while (cmd->cmd) {
		//if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
		if (strncasecmp(cmd->cmd, argv[0], 4) == 0) {
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}
	
	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = not_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
				0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
	} else {
		match->handler(ctrl, argc, &argv[0]);
	}
}

int not_process_command(char *msg)
{
	int argc = 2;

	not_cmd_handler(not_conn, argc, &msg);
}

static void not_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	not_recv_pending(not_conn);
}

static void not_close_connection(void)
{
	if (not_conn == NULL)
		return;

	if (not_attached) {
		wpa_ctrl_detach(not_conn);
		not_attached = 0;
	}
	eloop_unregister_read_sock(wpa_ctrl_get_fd(not_conn));
	wpa_ctrl_close(not_conn);
	not_conn = NULL;
}


static int not_open_connection(){
	char *cfile = NULL;
	int flen, res;
	
	
#ifdef ANDROID
	if (access(ctrl_iface_dir, F_OK) < 0) {
		cfile = os_strdup(SCKNAME);
		if (cfile == NULL)
			return -1;
	}
#endif /* ANDROID */
	
	if (cfile == NULL) {
		flen = os_strlen(ctrl_iface_dir) + os_strlen(SCKNAME) + 2;
		cfile = os_malloc(flen);
		if (cfile == NULL)
			return -1;
		res = os_snprintf(cfile, flen, "%s/%s", ctrl_iface_dir,
						  SCKNAME);

		if (res < 0 || res >= flen) {
			os_free(cfile);
			return -1;
		}
	}
	
	not_conn = wpa_ctrl_open(cfile);
	free(cfile);
	
	if(not_conn){
		if (wpa_ctrl_attach(not_conn) == 0) {
			not_attached = 1;
			//eloop_register_read_sock(wpa_ctrl_get_fd(not_conn),
		//							 not_receive, NULL, NULL);
		} else {
			printf("Warning: Failed to attach to "
				   "hostapd.\n");
			not_close_connection();
			return -1;
		}
	}

	return 0;

}

static void handle_not_response(char *buf, size_t len){
	char *ptr;
	time_t sec;
	u8 addr[ETH_ALEN];
	u32 mid;

	char out[2048];
	int loc;//, cloc;
	char *pos, *end;

	pos = out;
	end = pos + sizeof(out);

	ptr = os_strstr(buf, "Addr:");
	hwaddr_aton2(ptr + 5, addr);

	ptr = os_strstr(buf, "MID:");
	mid = atoi(ptr + 4);


	sec = time (NULL);
	
	ptr = os_strchr(buf, '-');

	loc = os_snprintf(pos, end - pos, "%ld: Response from " MACSTR " for notification id %u: %s", sec, MAC2STR(addr), mid, ptr+1);

	if(loc < 0 || loc > end - pos){
		return;
	 }

        //write(*pystub_sockfd, buf, len);

	printf("\r%s\n", out);
	
	
}

static void compute_notification(char *buf, size_t len){
	const char *pos;
	u8 addr[ETH_ALEN];
	int alen;
	char line[2048];
	time_t sec;
	int res;

	pos = os_strstr(buf, "Addr");

	if(pos == NULL){
		wpa_printf(MSG_ERROR, "Invalid incoming node message :%s", buf);
		return;
	}

	pos = os_strchr(pos, ':');

	pos++;

	if(len <= pos - buf){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	alen = hwaddr_aton2(pos, addr);

	if(alen < 0){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	sec = time (NULL);
	res = os_snprintf(line, 2048, "%ld: New node: " MACSTR, sec, MAC2STR(addr));
	line[res] = '\0';
	
	printf("\r%s\n", line);
	
	/*We can do expand this later with a connection to a third party server*/
	if(dynamic_test){
		char cmd[2048];

		os_snprintf(cmd, sizeof(cmd)-1, "PUSH " MACSTR "0 \"This is dynamic message %d\"", MAC2STR(addr), count++);
		not_command(not_conn, cmd);
	}
}

static void show_transmit(char *buf, size_t len){
	const char *pos;
	u8 addr[ETH_ALEN];
	int alen;
	u32 mid;
	int type;

	time_t sec;

	pos = os_strstr(buf, "Addr");

	if(pos == NULL){
		wpa_printf(MSG_ERROR, "Invalid incoming node message :%s", buf);
		return;
	}


	pos = os_strchr(pos, ':');

	pos++;

	if(len <= pos - buf){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	alen = hwaddr_aton2(pos, addr);

	if(alen < 0){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	pos = os_strstr(buf, "MID:");
	mid = atoi(pos + 4);

	sec = time (NULL);

	pos = os_strstr(buf, "Type:");
	type = atoi(pos+5);

	printf("\r%ld: SEND to " MACSTR " id:%u type:%s\n", sec, MAC2STR(addr), mid, type ? "Unicast":"Broadcast");

}

static void process_departing_node(char *buf, size_t len){
	const char *pos;
	u8 addr[ETH_ALEN];
	int alen;
	char line[2048];
	int res;

	time_t sec;

	pos = os_strstr(buf, "Addr");

	if(pos == NULL){
		wpa_printf(MSG_ERROR, "Invalid incoming node message :%s", buf);
		return;
	}


	pos = os_strchr(pos, ':');

	pos++;

	if(len <= pos - buf){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	alen = hwaddr_aton2(pos, addr);

	if(alen < 0){
		wpa_printf(MSG_ERROR, "Invalid node address");
		return;
	}

	sec = time (NULL);
	res = os_snprintf(line, 2048, "%ld: Departing node: " MACSTR, sec, MAC2STR(addr));
	line[res] = '\0';

	printf("\r%s\n", line);
}

static void process_incoming(char *buf, size_t len){
	
	char *pos = buf;

	if (os_strncmp(pos, "NEWNODE" , 7) == 0){
		compute_notification(pos + 7, len -7);
	} else if (os_strncmp(pos, "NOT_RESP" , 8) == 0){
		handle_not_response(pos+8, len - 8);
	} else if(os_strncmp(pos, "OLDNODE" , 7) == 0){
		process_departing_node(pos+7, len -7);
	} else if(os_strncmp(pos, "SENDMSG", 7 ) == 0 ){
		show_transmit(pos + 7, len -7);
	}else{
		printf("Unknown message %s\n", buf);
	}

}

static void cli_event(const char *str)
{
	const char *start, *s;

	start = os_strchr(str, '>');
	if (start == NULL)
		return;

	start++;

	if (str_starts(start, AP_STA_CONNECTED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		cli_txt_list_add(&stations, s + 1);
		return;
	}

	if (str_starts(start, AP_STA_DISCONNECTED)) {
		s = os_strchr(start, ' ');
		if (s == NULL)
			return;
		cli_txt_list_del_addr(&stations, s + 1);
		return;
	}
}


static void hostapd_cli_recv_pending(struct wpa_ctrl *ctrl, int in_read,
				     int action_monitor)
{
	int first = 1;
	if (not_conn == NULL)
		return;
	printf("Received message from sta\n");
	while (wpa_ctrl_pending(ctrl)) {
		char buf[4096];
		size_t len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';
			if (action_monitor)
				hostapd_cli_action_process(buf, len);
			else {
				cli_event(buf);
				if (in_read && first)
					printf("\n");
				first = 0;
				printf("Hostapd_cli: %s\n", buf);
			}
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}
}

static void hostapd_cli_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	hostapd_cli_recv_pending(not_conn, 0, 0);
}

static void not_recv_pending(struct wpa_ctrl *ctrl)
{
	printf("Notfier: not recv pending\n");
	if (not_conn == NULL)
		return;
	
	while (wpa_ctrl_pending(ctrl)) {
		char buf[2048];
		size_t len = 2047;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';

			process_incoming(buf, len);
			
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}
}

#define max_args 10

//static int tokenize_cmd(char *cmd, char *argv[])
//int tokenize_cmd(char *cmd, char *argv[])
//{
//	char *pos;
//	int argc = 0;
//	
//	pos = cmd;
//	for (;;) {
//		while (*pos == ' ')
//			pos++;
//		if (*pos == '\0')
//			break;
//		argv[argc] = pos;
//		argc++;
//		if (argc == max_args)
//			break;
//		if (*pos == '"') {
//			char *pos2 = os_strrchr(pos, '"');
//			if (pos2)
//				pos = pos2 + 1;
//		}
//		while (*pos != '\0' && *pos != ' ')
//			pos++;
//		if (*pos == ' ')
//			*pos++ = '\0';
//	}
//	
//	return argc;
//}

static void not_edit_cmd_cb(void *ctx, char *cmd)
{
	char *argv[max_args];
	int argc;
	argc = tokenize_cmd(cmd, argv);
	if (argc)
		not_cmd_handler(not_conn, argc, argv);
}


static void not_edit_eof_cb(void *ctx)
{
	eloop_terminate();
}

static void not_ping(void *eloop_ctx, void *timeout_ctx)
{
	if (not_conn && _not_command(not_conn, "PING", 0)) {
		printf("Connection to hostapd lost - trying to reconnect\n");
		not_close_connection();
	}
	if (!not_conn) {
		not_open_connection();
	}

	eloop_register_timeout(ping_interval, 0, not_ping, NULL, NULL);
}

static void not_init(void){

	edit_init(not_edit_cmd_cb, not_edit_eof_cb,
			  NULL, NULL, NULL, NULL);
	eloop_register_timeout(ping_interval, 0, not_ping, NULL, NULL);
	
	eloop_run();
	
	edit_deinit(NULL, NULL);
	eloop_cancel_timeout(not_ping, NULL, NULL);
}

static void not_terminate(int sig, void *ctx)
{
	eloop_terminate();
}


static void not_cleanup(void)
{
	not_close_connection();
	not_disconnect_pystub();
	os_program_deinit();
}

int wpa_not_init(char *msg)
{
	if (os_program_init())
		return -1;

	if (eloop_init())
		return -1;

	eloop_register_signal_terminate(not_terminate, NULL);

	if (not_open_connection() < 0){
		printf("Cannot start the connection\n");
		return -1;
	}
	register_event_handler(not_conn);

	printf("Connected hostapd successfully\n");
	not_init();

	not_connect_pystub();

	return 0;
}

int wpa_not_deinit()
{
	eloop_destroy();
	unregister_event_handler(not_conn);
	not_cleanup();
	os_program_deinit();

	return 0;
}

