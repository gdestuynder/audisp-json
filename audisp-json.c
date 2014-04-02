/* audisp-json.c --
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
#define MAX_ARG_LEN 512
#define MAX_ATTR_SIZE 1023
#define MAX_EXTRA_ATTR_SIZE 128
#define BUF_SIZE 32
#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION 1
#endif
#define USER_AGENT "audisp-json/PROGRAM_VERSION"

extern int h_errno;

static volatile int stop = 0;
static volatile int hup = 0;
static json_conf_t config;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static int machine = -1;

typedef struct	ll {
	char val[1024];
	struct ll *next;
} attr_t;

struct json_msg_type {
char	*hdr;
char	*type;
char	*app;
int	version;
char	*msgname;
char	*msgdesc;
int	severity;
struct	ll *attr;
time_t	au_time;
};

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

/* Post to mozdef */
int http_post(void)
{
	CURLcode ret;
	CURL *hnd;
	struct curl_slist *slist1;

	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Content-Type:application/json");

	hnd = curl_easy_init();
	curl_easy_setopt(hnd, CURLOPT_URL, "http://localhost:8080/events");
	curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, "");
	curl_easy_setopt(hnd, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
	curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
	curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);

	/* Here is a list of options the curl code used that cannot get generated
	   as source easily. You may select to either not use them or implement
	   them yourself.

	   CURLOPT_WRITEDATA set to a objectpointer
	   CURLOPT_WRITEFUNCTION set to a functionpointer
	   CURLOPT_READDATA set to a objectpointer
	   CURLOPT_READFUNCTION set to a functionpointer
	   CURLOPT_SEEKDATA set to a objectpointer
	   CURLOPT_SEEKFUNCTION set to a functionpointer
	   CURLOPT_ERRORBUFFER set to a objectpointer
	   CURLOPT_STDERR set to a objectpointer
	   CURLOPT_HEADERFUNCTION set to a functionpointer
	   CURLOPT_HEADERDATA set to a objectpointer

*/

	ret = curl_easy_perform(hnd);

	curl_easy_cleanup(hnd);
	hnd = NULL;
	curl_slist_free_all(slist1);
	slist1 = NULL;

	return (int)ret;
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
	struct sigaction sa;
	struct hostent *ht;
	char nodename[64];

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;

	openlog("audisp-json", LOG_CONS, config.facility);

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
		return 1;

	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		syslog(LOG_ERR, "could not initialize auparse");
		free_config(&config);
		return -1;
	}
   
	machine = audit_detect_machine();
	if (machine < 0)
		return -1;

	auparse_add_callback(au, handle_event, NULL, NULL);

	syslog(LOG_INFO, "audisp-json loaded\n");
	do {
		if (hup)
			reload_config();

		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0)
			auparse_feed(au, tmp, strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));

		if (feof(stdin))
			break;
	} while (stop == 0);

	syslog(LOG_INFO, "audisp-json unloaded\n");
	closelog();
	auparse_flush_feed(au);
	auparse_destroy(au);
	free_config(&config);

	return 0;
}

int add_extra_record(auparse_state_t *au, char *extra, char *attr)
{
	size_t len = strlen(extra);
	size_t attr_len = strlen(attr) ? MAX_EXTRA_ATTR_SIZE:MAX_EXTRA_ATTR_SIZE;

	if ((len+attr_len) > MAX_ATTR_SIZE)
		return 1;
	snprintf(extra+len, attr_len, " %s\\=%s", attr, auparse_find_field(au, attr));
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

char *unescape(const char *in)
{
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

attr_t *json_add_attr(attr_t *list, const char *st, const char *val)
{
	attr_t *new;

	if (val == NULL)
			return list;
	if (strstr(val, "(null)") != NULL)
			return list;

	new = malloc(sizeof(attr_t));
	snprintf(new->val, MAX_ATTR_SIZE, "%s%s ", st, unescape(val));
	new->next = list;
	return new;
}

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

char *get_proc_name(int pid)
{
	char p[1024];
	static char proc[64];
	FILE *fp;
	snprintf(p, 512, "/proc/%d/status", pid);
	fp = fopen(p, "r");
	if (fp) {
		fscanf(fp, "Name: %63s", proc);
		fclose(fp);
	} else
		return NULL;
	return proc;
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

void syslog_json_msg(struct json_msg_type json_msg)
{
	attr_t *head = json_msg.attr;
	attr_t *prev;
	char msg[1500];

	snprintf(msg, 1500, "%s|%s|%s|%u|%s|%s|%u|end=%ld ", json_msg.hdr, json_msg.type, json_msg.app,
		json_msg.version, json_msg.msgname, json_msg.msgdesc, json_msg.severity, json_msg.au_time);
	while (head) {
			snprintf(msg+strlen(msg), 1500, "%s", head->val);
			prev = head;
			head = head->next;
			free(prev);
	}
	syslog(LOG_INFO, "%s", msg);
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num=0;
	time_t au_time;

	struct json_msg_type json_msg = {
		.severity	= 3,
	};

	const char *cwd = NULL, *argc = NULL, *cmd = NULL;
	const char *sys;
	const char *syscall = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	char fullcmdt[5] = "No\0";
	char extra[MAX_ARG_LEN] = "\0";

	char f[8];
	int len, tmplen;
	int argcount, i;
	int havejson = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	while (auparse_goto_record_num(au, num) > 0) {
		extra[0] = '\0';
		type = auparse_get_type(au);
		rc = 0;
		auparse_first_field(au);
		json_msg.au_time = auparse_get_time(au);
		switch (type) {
		   	case AUDIT_AVC:
				argc = auparse_find_field(au, "apparmor");
				if (!argc)
					return;

				havejson = 1;
				json_msg.msgname = "AVC_APPARMOR";

				json_msg.attr = json_add_attr(json_msg.attr, "cs1Label=Result cs1=", auparse_get_field_str(au));
				goto_record_type(au, type);

				json_msg.msgdesc = unescape(auparse_find_field(au, "info"));
				goto_record_type(au, type);

				json_msg.attr = json_add_attr(json_msg.attr, "cs2Label=Operation cs2=", auparse_find_field(au, "operation"));
				goto_record_type(au, type);

				json_msg.attr = json_add_attr(json_msg.attr, "cs3Label=Profile cs3=", auparse_find_field(au, "profile"));
				goto_record_type(au, type);

				json_msg.attr = json_add_attr(json_msg.attr, "cs4Label=Command cs4=", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "parent"))
					json_msg.attr = json_add_attr(json_msg.attr, "sproc=", get_proc_name(auparse_get_field_int(au)));
				goto_record_type(au, type);

				if (auparse_find_field(au, "pid"))
					json_msg.attr = json_add_attr(json_msg.attr, "dproc=", get_proc_name(auparse_get_field_int(au)));
				goto_record_type(au, type);

				add_extra_record(au, extra, "error");
				goto_record_type(au, type);
				add_extra_record(au, extra, "name");
				goto_record_type(au, type);
				add_extra_record(au, extra, "srcname");
				goto_record_type(au, type);
				add_extra_record(au, extra, "flags");
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
					} else
							strncpy(fullcmdt, "Yes\0", 4);
				}
				json_msg.attr = json_add_attr(json_msg.attr, "cs2Label=Truncated cs2=", fullcmdt);
				json_msg.attr = json_add_attr(json_msg.attr, "cs1Label=Command cs1=", fullcmd);
				break;
			case AUDIT_CWD:
				cwd = auparse_find_field(au, "cwd");
				if (cwd) {
					auparse_interpret_field(au);
					add_extra_record(au, extra, "cwd");
				}
				break;
			case AUDIT_PATH:
				json_msg.attr = json_add_attr(json_msg.attr, "fname=", auparse_find_field(au, "name"));
				goto_record_type(au, type);

				add_extra_record(au, extra, "inode");
				goto_record_type(au, type);
				add_extra_record(au, extra, "dev");
				goto_record_type(au, type);
				add_extra_record(au, extra, "mode");
				goto_record_type(au, type);
				add_extra_record(au, extra, "ouid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "ogid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "rdev");
				goto_record_type(au, type);
				break;
			case AUDIT_SYSCALL:
				syscall = auparse_find_field(au, "syscall");
				if (!syscall) {
					json_del_attrs(json_msg.attr);
					return;
				}
				i = auparse_get_field_int(au);
				sys = audit_syscall_to_name(i, machine);
				if (!sys) {
					syslog(LOG_INFO, "Unknown system call %u", i);
					json_del_attrs(json_msg.attr);
					return;
				}

				if (!strncmp(sys, "write", 5) || !strncmp(sys, "open", 4) || !strncmp(sys, "unlink", 6)) {
					havejson = i;
					json_msg.msgname = "WRITE";
					json_msg.msgdesc = "Write or append to file";
				} else if (!strncmp(sys, "setxattr", 8)) {
					havejson = i;
					json_msg.msgname = "ATTR";
					json_msg.msgdesc = "Change file attributes";
				} else if (!strncmp(sys, "chmod", 5)) {
					havejson = i;
					json_msg.msgname = "CHMOD";
					json_msg.msgdesc = "Change file mode";
				} else if (!strncmp(sys, "chown", 5)) {
					havejson = i;
					json_msg.msgname = "CHOWN";
					json_msg.msgdesc = "Change file owner";
				} else if (!strncmp(sys, "ptrace",  6)) {
					havejson = i;
					json_msg.msgname = "PTRACE";
					json_msg.msgdesc = "Process tracing";
				} else if (!strncmp(sys, "execve", 6)) {
					havejson = i;
					json_msg.msgname = "EXECVE";
					json_msg.msgdesc = "Unix Exec";
				} else {
					syslog(LOG_INFO, "Unhandled system call %u %s", i, sys);
				}

				json_msg.attr = json_add_attr(json_msg.attr, "cs3Label=AuditKey cs3=", auparse_find_field(au, "key"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "ppid"))
					json_msg.attr = json_add_attr(json_msg.attr, "cs5Label=ParentProcess cs5=", get_proc_name(auparse_get_field_int(au)));
				goto_record_type(au, type);

				if (auparse_find_field(au, "auid")) {
					json_msg.attr = json_add_attr(json_msg.attr, "suser=", get_username(auparse_get_field_int(au)));
					json_msg.attr = json_add_attr(json_msg.attr, "cn1Label=auid cn1=",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.attr = json_add_attr(json_msg.attr, "duser=", get_username(auparse_get_field_int(au)));
					json_msg.attr = json_add_attr(json_msg.attr, "duid=", auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				json_msg.attr = json_add_attr(json_msg.attr, "cs4Label=TTY cs4=", auparse_find_field(au, "tty"));
				goto_record_type(au, type);
				json_msg.attr = json_add_attr(json_msg.attr, "dproc=", auparse_find_field(au, "exe"));
				goto_record_type(au, type);

				add_extra_record(au, extra, "pid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "gid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "euid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "suid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "fsuid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "egid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "sgid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "fsgid");
				goto_record_type(au, type);
				add_extra_record(au, extra, "ses");
				goto_record_type(au, type);
				break;
			default:
				break;
		}
		num++;
	}

	if (!havejson) {
		json_del_attrs(json_msg.attr);
		return;
	}

	if (strlen(extra) >= MAX_ARG_LEN) {
		extra[MAX_ARG_LEN] = '\0';
		json_msg.attr = json_add_attr(json_msg.attr, "cs6Label=MsgTruncated cs6=", "Yes");
	}
	json_msg.attr = json_add_attr(json_msg.attr, "msg=", extra);
	json_msg.attr = json_add_attr(json_msg.attr, "dhost=", hostname);
	//This also frees json_msg.attr
	syslog_json_msg(json_msg);
}
