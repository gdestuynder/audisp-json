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
#define MAX_JSON_MSG_SIZE 2048
#define MAX_ARG_LEN 2048
#define MAX_ATTR_SIZE 1023
#define BUF_SIZE 32
#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION 1
#endif
#ifndef PROGRAME_NAME
#define PROGRAM_NAME "audisp-json"
#endif
#define USER_AGENT "PROGRAM_NAME/PROGRAM_VERSION"

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
	char	*category;
	char	*summary;
	char	*severity;
	char	*hostname;
	int		processid;
	char	*processname;
	char	*timestamp;
	struct	ll *details;
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

	syslog(LOG_INFO, "%s loaded\n", PROGRAM_NAME);
	do {
		if (hup)
			reload_config();

		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0)
			auparse_feed(au, tmp, strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));

		if (feof(stdin))
			break;
	} while (stop == 0);

	syslog(LOG_INFO, "%s unloaded\n", PROGRAM_NAME);
	closelog();
	auparse_flush_feed(au);
	auparse_destroy(au);
	free_config(&config);

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
	snprintf(new->val, MAX_ATTR_SIZE, "\t\t\"%s\": \"%s\"", st, unescape(val));
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

int syslog_json_msg(struct json_msg_type json_msg)
{
	attr_t *head = json_msg.details;
	attr_t *prev;
	char msg[MAX_JSON_MSG_SIZE];
	CURLcode ret;
	CURL *hnd;
	struct curl_slist *slist1;

	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Content-Type:application/json");

	hnd = curl_easy_init();
	curl_easy_setopt(hnd, CURLOPT_URL, config.mozdef_url);
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

	snprintf(msg, MAX_JSON_MSG_SIZE,
"{\n\
	\"category\": \"%s\",\n\
	\"summary\": \"%s\",\n\
	\"severity\": \"%s\",\n\
	\"hostname\": \"%s\",\n\
	\"processid\": \"%u\",\n\
	\"processname\": \"%s\",\n\
	\"timestamp\": \"%s\",\n\
	\"tags\": [\n\
		\"%s\",\n\
		\"%u\",\n\
		\"audit\"\n\
	],\n\
	\"details\": {",
		json_msg.category, json_msg.summary, json_msg.severity, json_msg.hostname, json_msg.processid,
		json_msg.processname, json_msg.timestamp, PROGRAM_NAME, PROGRAM_VERSION);

	while (head) {
			snprintf(msg+strlen(msg), MAX_JSON_MSG_SIZE, "\n%s,", head->val);
			prev = head;
			head = head->next;
			free(prev);

			if (head == NULL) {
				msg[strlen(msg)-1] = '\n';
			}
	}
	snprintf(msg+strlen(msg), MAX_JSON_MSG_SIZE, "	}\n}");

	ret = curl_easy_perform(hnd);
	curl_easy_cleanup(hnd);
	hnd = NULL;
	curl_slist_free_all(slist1);
	slist1 = NULL;

	printf("%s\n", msg);
	return (int)ret;
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num=0;
	time_t au_time;

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

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	json_msg.timestamp = (char *)alloca(64);

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		rc = 0;
		auparse_first_field(au);
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
					json_msg.details = json_add_attr(json_msg.details, "parentprocess", get_proc_name(auparse_get_field_int(au)));
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
					havejson = i;
					json_msg.category = "write";
					json_msg.summary = "Write or append to file";
				} else if (!strncmp(sys, "setxattr", 8)) {
					havejson = i;
					json_msg.category = "attribute";
					json_msg.summary = "Change file attributes";
				} else if (!strncmp(sys, "chmod", 5)) {
					havejson = i;
					json_msg.category = "chmod";
					json_msg.summary = "Change file mode";
				} else if (!strncmp(sys, "chown", 5)) {
					havejson = i;
					json_msg.category = "chown";
					json_msg.summary = "Change file owner";
				} else if (!strncmp(sys, "ptrace",  6)) {
					havejson = i;
					json_msg.category = "ptrace";
					json_msg.summary = "Process tracing";
				} else if (!strncmp(sys, "execve", 6)) {
					havejson = i;
					json_msg.category = "execve";
					json_msg.summary = "Execute new process";
				} else {
					syslog(LOG_INFO, "System call %u %s is not supported by %s", i, sys, PROGRAM_NAME);
				}

				json_msg.details = json_add_attr(json_msg.details, "auditkey", auparse_find_field(au, "key"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "ppid"))
					json_msg.details = json_add_attr(json_msg.details, "parentprocess", get_proc_name(auparse_get_field_int(au)));
				goto_record_type(au, type);

				if (auparse_find_field(au, "auid")) {
					json_msg.details = json_add_attr(json_msg.details, "originaluser", get_username(auparse_get_field_int(au)));
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
	if (!syslog_json_msg(json_msg))
		syslog(LOG_WARNING, "failed to send json message");
}
