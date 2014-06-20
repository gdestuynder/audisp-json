/* vim: ts=4:sw=4:noexpandtab
 * audisp-json.c --
 * Copyright (c) 2014 Mozilla Corporation.
 * Portions Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Guillaume Destuynder <gdestuynder@mozilla.com>
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <time.h>
#include <curl/curl.h>
#include "libaudit.h"
#include "auparse.h"
#include "json-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-json.conf"
#define CONFIG_FILE_LOCAL "audisp-json.conf"
// after this amount of time for any response (connect, http reply, etc.) just give up
// and lose messages.
// don't set this too high as new curl handles will be created and consume memory while 
// waiting for the connection to work again.
#define MAX_CURL_GLOBAL_TIMEOUT 5000L
#define RING_BUF_LEN 512
#define MAX_JSON_MSG_SIZE 4096
#define MAX_ARG_LEN 2048
#define MAX_SUMMARY_LEN 256
#define MAX_ATTR_SIZE 1023
#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "1"
#endif
#ifndef PROGRAME_NAME
#define PROGRAM_NAME "audisp-json"
#endif
/* transform macro int and str value to ... str */
#define _STR(x) #x
#define STR(x) _STR(x)
#define USER_AGENT PROGRAM_NAME"/"STR(PROGRAM_VERSION)

extern int h_errno;

static volatile int stop = 0;
static volatile int hup = 0;
static json_conf_t config;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static int machine = -1;

static long int curl_timeout = -1;
int curl_nr_h = 0;
CURLM *multi_h;
CURL *easy_h;
struct curl_slist *slist1;

typedef struct { char *val; } msg_t;
typedef struct ring_buf_msg {
	int size;
	int start;
	int end;
	msg_t *data;
} ring_buf_msg_t;

static ring_buf_msg_t msg_list;

typedef struct	ll {
	char val[MAX_ATTR_SIZE];
	struct ll *next;
} attr_t;

struct json_msg_type {
	char	*category;
	char	*summary;
	char	*severity;
	char	*hostname;
	int		processid;
	char	*processname;
	char	*timestamp;
	struct	ll *details;
};

/* ring buffer functions */

int ring_full(ring_buf_msg_t *rb)
{
	return (rb->end + 1) % rb->size == rb->start;
}

int ring_empty(ring_buf_msg_t *rb)
{
	if ((rb->end-1) == rb->start) {
		return 1;
	}
	return 0;
}

void ring_add(ring_buf_msg_t *rb, char *val)
{
	msg_t data = {0};
	data.val = val;

	rb->data[rb->end] = data;
	rb->end = (rb->end + 1) % rb->size;
	if (rb->end == rb->start) {
		rb->start = (rb->start + 1) % rb->size;
	}
}

char *ring_read(ring_buf_msg_t *rb)
{
	char *val;
	val = rb->data[rb->start].val;
	rb->start = (rb->start + 1) % rb->size;
	return val;
}

void prepare_curl_handle(void)
{
	curl_easy_reset(easy_h);
	curl_easy_setopt(easy_h, CURLOPT_URL, config.mozdef_url);
	curl_easy_setopt(easy_h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(easy_h, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt(easy_h, CURLOPT_HTTPHEADER, slist1);
	curl_easy_setopt(easy_h, CURLOPT_MAXREDIRS, 10L);
	curl_easy_setopt(easy_h, CURLOPT_CUSTOMREQUEST, "POST");
/* keep alive is on by default and only settable in recent libcurl
 * keeping this around in case its not actually default in some cases and needs
 * to be conditionally enabled
 */
//	curl_easy_setopt(easy_h, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(easy_h, CURLOPT_VERBOSE, config.curl_verbose);
	curl_easy_setopt(easy_h, CURLOPT_TIMEOUT_MS, MAX_CURL_GLOBAL_TIMEOUT);
	curl_easy_setopt(easy_h, CURLOPT_SSL_VERIFYHOST, config.ssl_verify);
	curl_easy_setopt(easy_h, CURLOPT_SSL_VERIFYPEER, config.ssl_verify);
}

/* select and fetch urls */
void curl_perform(void)
{
	int msgs_left;
	int maxfd = -1;
	struct timeval timeout;
	int rc;
	CURLMsg *msg;
	CURL *eh;
	CURLcode ret;

	while (curl_nr_h > 0) {
		fd_set r, w, e;
		FD_ZERO(&r);
		FD_ZERO(&w);
		FD_ZERO(&e);

		ret = curl_multi_timeout(multi_h, &curl_timeout);
		if (ret != CURLM_OK) {
			syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
		}
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (curl_timeout >= 0) {
			timeout.tv_sec = curl_timeout / 1000;
			if (timeout.tv_sec > 1)
				timeout.tv_sec = 1;
			else
				timeout.tv_usec = (curl_timeout % 1000) * 1000;
		}
		ret = curl_multi_fdset(multi_h, &r, &w, &e, &maxfd);
		if (ret != CURLM_OK) {
			syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
			return;
		}

		rc = select(maxfd+1, &r, &w, &e, &timeout);

		switch(rc) {
			case -1:
				syslog(LOG_ERR, "%s", strerror(errno));
				break;
			case 0:
			default:
				ret = curl_multi_perform(multi_h, &curl_nr_h);
				if (ret != CURLM_OK) {
					syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
				}
				break;
		}
	}

	/* Cleanup completed handles */
	while (msg = curl_multi_info_read(multi_h, &msgs_left)) {
		if (msg->msg == CURLMSG_DONE) {
			if (!ring_empty(&msg_list)) {
				char *new_msg = ring_read(&msg_list);
				curl_multi_remove_handle(multi_h, easy_h);
				prepare_curl_handle();
				curl_easy_setopt(easy_h, CURLOPT_POSTFIELDS, new_msg);
				curl_easy_setopt(easy_h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(new_msg));
				free(new_msg);
				curl_nr_h++;
				curl_multi_add_handle(multi_h, easy_h);
			}
		}
	}
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

static void term_handler( int sig )
{
	stop = 1;
}

static void hup_handler( int sig )
{
	hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

/* find string distance from *in until char c is reached */
unsigned int strstok(char *in, char c)
{
	unsigned int slen, len = 0;

	if (in == NULL)
		return len;

	slen = strlen(in);

	while (in[len] != c && len <= slen)
		len++;
	len++;
	return len;
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	int len=0;
	struct sigaction sa;
	struct hostent *ht;
	char nodename[64];
	CURLMcode ret;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;

	openlog(PROGRAM_NAME, LOG_CONS, LOG_DAEMON);

	if (gethostname(nodename, 63)) {
		snprintf(nodename, 10, "localhost");
	}
	nodename[64] = '\0';
	ht = gethostbyname(nodename);
	if (ht == NULL) {
		hostname = strdup("localhost");
		syslog(LOG_ALERT,
			"gethostbyname could not find machine hostname, please fix this. Using %s as fallback. Error: %s",
			hostname, hstrerror(h_errno));
	} else {
		hostname = strdup(ht->h_name);
	}

	if (load_config(&config, CONFIG_FILE))
		if (load_config(&config, CONFIG_FILE_LOCAL))
			return 1;

	au = auparse_init(AUSOURCE_FEED, NULL);
	if (au == NULL) {
		syslog(LOG_ERR, "could not initialize auparse");
		return -1;
	}

	machine = audit_detect_machine();
	if (machine < 0) {
		return -1;
	}

	/* libcurl stuff */
	msg_list.size = RING_BUF_LEN;
	msg_list.start = 0;
	msg_list.end = 0;
	msg_list.data = (msg_t *)calloc(RING_BUF_LEN, sizeof(msg_t));

	if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
		syslog(LOG_ERR, "curl_global_init() failed");
		return -1;
	}

	easy_h = curl_easy_init();
	multi_h = curl_multi_init();
	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Content-Type:application/json");
	if (!(easy_h && multi_h && slist1)) {
		syslog(LOG_ERR, "cURL handles creation failed, this is fatal.");
		return -1;
	}
	prepare_curl_handle();
	curl_nr_h = 1;
	ret = curl_multi_add_handle(multi_h, easy_h);
	if (ret != CURLM_OK) {
		syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
		return -1;
	}

	auparse_add_callback(au, handle_event, NULL, NULL);
	syslog(LOG_INFO, "%s loaded\n", PROGRAM_NAME);

	do {
		if (hup)
			reload_config();

		/* Note: auparse matches on the complete record field in order to associate all matching records into one
		 * message. This means both the timestamp and the record serial (UUID) must match. If for some reason the kernel
		 * sends various records for the same event at a different time, the messages will be processed as 2 separate
		 * messages even thus the record serial matches.
		 */
		while ((len = fread_unlocked(tmp, 1, MAX_AUDIT_MESSAGE_LENGTH, stdin))) {
			auparse_feed(au, tmp, len);
		}

		if (feof(stdin))
			break;
	} while (stop == 0);

	auparse_flush_feed(au);

	while (!ring_empty(&msg_list)) {
		curl_perform();
	}

	auparse_destroy(au);
	curl_global_cleanup();
	free(msg_list.data);
	free_config(&config);
	free(hostname);
	syslog(LOG_INFO, "%s unloaded\n", PROGRAM_NAME);
	closelog();

	return 0;
}

/*
 * This function seeks to the specified record returning its type on succees
 */
static int goto_record_type(auparse_state_t *au, int type)
{
	int cur_type;

	auparse_first_record(au);
	do {
		cur_type = auparse_get_type(au);
		if (cur_type == type) {
			auparse_first_field(au);
			return type;  // Normal exit
		}
	} while (auparse_next_record(au) > 0);

	return -1;
}

/* Removes quotes */
char *unescape(const char *in)
{
	if (in == NULL)
		return "(null)";

	char *dst = (char *)in;
	char *s = dst;
	char *src = (char *)in;
	char c;

	while ((c = *src++) != '\0') {
		if (c != '"')
			*dst++ = c;
	}
	*dst = '\0';
	return s;
}

/* Add a field to the json msg's details={} */
attr_t *json_add_attr(attr_t *list, const char *st, const char *val)
{
	attr_t *new;

	new = malloc(sizeof(attr_t));
	snprintf(new->val, MAX_ATTR_SIZE, "\t\t\"%s\": \"%s\"", st, unescape(val));
	new->next = list;
	return new;
}

void json_del_attrs(attr_t *head)
{
	attr_t *prev;
	while (head) {
		prev = head;
		head = head->next;
		free(prev);
	}
}

/* Resolve uid to username */
char *get_username(int uid)
{
	size_t bufsize;
	char *buf;
	char *name;
	struct passwd pwd;
	struct passwd *result;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;
	buf = (char *)alloca(bufsize);

	if (uid == -1) {
		return NULL;
	}
	if (getpwuid_r(uid, &pwd, buf, bufsize, &result) != 0) {
		return NULL;
	}
	if (result == NULL) {
		return NULL;
	}
	name = strdupa(pwd.pw_name);
	return name;
}

/* Resolve process name from pid */
char *get_proc_name(int pid)
{
	char p[1024];
	int ret;
	static char proc[64];
	FILE *fp;
	snprintf(p, 512, "/proc/%d/status", pid);
	fp = fopen(p, "r");
	if (fp) {
		ret = fscanf(fp, "Name: %63s", proc);
		fclose(fp);
	} else
		return NULL;

	if (ret == 0)
		return NULL;

	return proc;
}

void syslog_json_msg(struct json_msg_type json_msg)
{
	attr_t *head = json_msg.details;
	attr_t *prev;
	char *msg;
	int len;

	msg = malloc((size_t)MAX_JSON_MSG_SIZE);

	len = snprintf(msg, MAX_JSON_MSG_SIZE,
"{\n\
	\"category\": \"%s\",\n\
	\"summary\": \"%s\",\n\
	\"severity\": \"%s\",\n\
	\"hostname\": \"%s\",\n\
	\"processid\": \"%i\",\n\
	\"processname\": \"%s\",\n\
	\"timestamp\": \"%s\",\n\
	\"tags\": [\n\
		\"%s\",\n\
		\"%s\",\n\
		\"audit\"\n\
	],\n\
	\"details\": {",
		json_msg.category, json_msg.summary, json_msg.severity, json_msg.hostname, json_msg.processid,
		json_msg.processname, json_msg.timestamp, PROGRAM_NAME, PROGRAM_VERSION);

	while (head) {
			len += snprintf(msg+len, MAX_JSON_MSG_SIZE, "\n%s,", head->val);
			prev = head;
			head = head->next;
			free(prev);

			if (head == NULL) {
				msg[len-1] = '\n';
			}
	}

	len += snprintf(msg+len, MAX_JSON_MSG_SIZE, "	}\n}");
	msg[MAX_JSON_MSG_SIZE-1] = '\0';

	ring_add(&msg_list, msg);
#ifdef DEBUG
	printf("%s\n", msg);
#endif
}

/* The main event handling, parsing, collerating function */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num=0;

	struct json_msg_type json_msg = {
		.category		= NULL,
		.hostname		= hostname,
		.processid		= 0,
		.processname	= NULL,
		.severity		= "INFO",
		.summary		= NULL,
		.timestamp		= NULL,
		.details		= NULL,
	};

	const char *cwd = NULL, *argc = NULL, *cmd = NULL;
	const char *sys;
	const char *syscall = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	time_t t;
	struct tm *tmp;

	char f[8];
	int len, tmplen;
	int argcount, i;
	int havejson = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY) {
		printf("try again later\n");
		return;
	}

	json_msg.timestamp = (char *)alloca(64);
	json_msg.summary = (char *)alloca(MAX_SUMMARY_LEN);

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		rc = 0;

		if (!auparse_first_field(au))
			continue;

		t = auparse_get_time(au);
		tmp = localtime(&t);
		strftime(json_msg.timestamp, 64, "%FT%T%z", tmp);

		switch (type) {
			case AUDIT_AVC:
				argc = auparse_find_field(au, "apparmor");
				if (!argc)
					return;

				havejson = 1;
				json_msg.category = "AVC_APPARMOR";

				json_msg.details = json_add_attr(json_msg.details, "aaresult", auparse_get_field_str(au));
				goto_record_type(au, type);

				json_msg.summary = unescape(auparse_find_field(au, "info"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aacoperation", auparse_find_field(au, "operation"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aaprofile", auparse_find_field(au, "profile"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aacommand", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "parent"))
					json_msg.details = json_add_attr(json_msg.details, "parentprocess",
														get_proc_name(auparse_get_field_int(au)));

				goto_record_type(au, type);

				if (auparse_find_field(au, "pid"))
					json_msg.processname = get_proc_name(auparse_get_field_int(au));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aaerror", auparse_find_field(au, "error"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aaname", auparse_find_field(au, "name"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aasrcname", auparse_find_field(au, "srcname"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aaflags", auparse_find_field(au, "flags"));
				goto_record_type(au, type);
				break;
			case AUDIT_EXECVE:
				argc = auparse_find_field(au, "argc");
				if (argc)
					argcount = auparse_get_field_int(au);
				else
					argcount = 0;
				fullcmd[0] = '\0';
				len = 0;
				for (i = 0; i != argcount; i++) {
					goto_record_type(au, type);
					tmplen = snprintf(f, 7, "a%d", i);
					f[tmplen] = '\0';
					cmd = auparse_find_field(au, f);
					cmd = auparse_interpret_field(au);
					if (!cmd)
						continue;
					if (MAX_ARG_LEN-strlen(fullcmd) > strlen(cmd)) {
						if (len == 0)
							len += sprintf(fullcmd+len, "%s", cmd);
						else
							len += sprintf(fullcmd+len, " %s", cmd);
					}
				}
				json_msg.details = json_add_attr(json_msg.details, "command", fullcmd);
				break;
			case AUDIT_CWD:
				cwd = auparse_find_field(au, "cwd");
				if (cwd) {
					auparse_interpret_field(au);
					json_msg.details = json_add_attr(json_msg.details, "cwd", auparse_find_field(au, "cwd"));
				}
				break;
			case AUDIT_PATH:
				json_msg.details = json_add_attr(json_msg.details, "path", auparse_find_field(au, "name"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "inode", auparse_find_field(au, "inode"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "dev", auparse_find_field(au, "dev"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "mode", auparse_find_field(au, "mode"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "ouid", auparse_find_field(au, "ouid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "ogid", auparse_find_field(au, "ogid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "rdev", auparse_find_field(au, "rdev"));
				goto_record_type(au, type);
				break;
			case AUDIT_SYSCALL:
				syscall = auparse_find_field(au, "syscall");
				if (!syscall) {
					json_del_attrs(json_msg.details);
					return;
				}
				i = auparse_get_field_int(au);
				sys = audit_syscall_to_name(i, machine);
				if (!sys) {
					syslog(LOG_INFO, "System call %u is not supported by %s", i, PROGRAM_NAME);
					json_del_attrs(json_msg.details);
					return;
				}

				if (!strncmp(sys, "write", 5) || !strncmp(sys, "open", 4) || !strncmp(sys, "unlink", 6)) {
					havejson = 1;
					json_msg.category = "write";
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Write or append to file");
				} else if (!strncmp(sys, "setxattr", 8)) {
					havejson = 1;
					json_msg.category = "attribute";
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Change file attributes");
				} else if (!strncmp(sys, "chmod", 5)) {
					havejson = 1;
					json_msg.category = "chmod";
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Change file mode");
				} else if (!strncmp(sys, "chown", 5)) {
					havejson = 1;
					json_msg.category = "chown";
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Change file owner");
				} else if (!strncmp(sys, "ptrace",  6)) {
					havejson = 1;
					json_msg.category = "ptrace";
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Process tracing");

				} else if (!strncmp(sys, "execve", 6)) {
					havejson = 1;
					json_msg.category = "execve";
					auparse_find_field(au, "comm");
					snprintf(json_msg.summary,
								MAX_SUMMARY_LEN,
								"Execute new process: %s",
								unescape(auparse_get_field_str(au)));

				} else {
					syslog(LOG_INFO, "System call %u %s is not supported by %s", i, sys, PROGRAM_NAME);
				}

				json_msg.details = json_add_attr(json_msg.details, "auditkey", auparse_find_field(au, "key"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "ppid"))
					json_msg.details = json_add_attr(json_msg.details, "parentprocess",
														get_proc_name(auparse_get_field_int(au)));

				goto_record_type(au, type);

				if (auparse_find_field(au, "auid")) {
					json_msg.details = json_add_attr(json_msg.details, "originaluser",
														get_username(auparse_get_field_int(au)));

					json_msg.details = json_add_attr(json_msg.details, "originaluid",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.details = json_add_attr(json_msg.details, "user", get_username(auparse_get_field_int(au)));
					json_msg.details = json_add_attr(json_msg.details, "uid", auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "tty", auparse_find_field(au, "tty"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "process", auparse_find_field(au, "exe"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "pid", auparse_find_field(au, "pid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "gid", auparse_find_field(au, "gid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "euid", auparse_find_field(au, "euid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "suid", auparse_find_field(au, "suid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "fsuid", auparse_find_field(au, "fsuid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "egid", auparse_find_field(au, "egid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "sgid", auparse_find_field(au, "sgid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "fsgid", auparse_find_field(au, "fsgid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "session", auparse_find_field(au, "ses"));
				goto_record_type(au, type);
				break;
			default:
				break;
		}
		num++;
	}

	if (!havejson) {
		json_del_attrs(json_msg.details);
		return;
	}

	//This also frees json_msg.details
	syslog_json_msg(json_msg);

	/* if we have no traffic going on lets start some 
	 * otherwise, traffic is queued in the select loop at curl_perform()
	 */
	if (curl_nr_h <= 0) {
		char *msg = ring_read(&msg_list);

		curl_multi_remove_handle(multi_h, easy_h);
		prepare_curl_handle();
		curl_easy_setopt(easy_h, CURLOPT_POSTFIELDS, msg);
		curl_easy_setopt(easy_h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(msg));
		free(msg);
		curl_nr_h++;
		curl_multi_add_handle(multi_h, easy_h);
	}
	curl_perform();
}
