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
#include <sys/socket.h>
#include <time.h>
#include <curl/curl.h>
#include "libaudit.h"
#include "auparse.h"
#include "json-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-json.conf"
#define CONFIG_FILE_LOCAL "audisp-json.conf"
/* after this amount of time for any response (connect, http reply, etc.) just give up
 * and lose messages.
 * don't set this too high as new curl handles will be created and consume memory while 
 * waiting for the connection to work again.
 */
#define MAX_CURL_GLOBAL_TIMEOUT 5000L
#define MAX_CURL_QUEUE_SIZE 8192
#define MAX_JSON_MSG_SIZE 4096
#define MAX_ARG_LEN 2048
#define MAX_SUMMARY_LEN 256
#define TS_LEN 64
#define MAX_ATTR_SIZE MAX_AUDIT_MESSAGE_LENGTH
#ifdef REORDER_HACK
#define NR_LINES_BUFFERED 64
#endif

#define HTTP_CODE_OK 200

#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "1"
#endif
#ifndef PROGRAM_NAME
#define PROGRAM_NAME "audisp-json"
#endif
/* transform macro int and str value to ... str - needed for defining USER_AGENT ;)*/
#define _STR(x) #x
#define STR(x) _STR(x)
#define USER_AGENT PROGRAM_NAME"/"STR(PROGRAM_VERSION)

extern int h_errno;

static volatile int sig_stop = 0;
static volatile int sig_hup = 0;
static json_conf_t config;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static int machine = -1;

static long int curl_timeout = -1;
FILE *curl_logfile;
FILE *file_log;
CURLM *multi_h;
CURL *easy_h;
struct curl_slist *slist1;
int curl_nr_h = -1;
int msg_lost = 0;

typedef struct { char *val; } msg_t;

/* msg attributes list */
typedef struct	ll {
	char value[MAX_ATTR_SIZE];
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

/* msgs to send queue/buffer */
typedef struct lq {
	char msg[MAX_JSON_MSG_SIZE];
	struct lq *next;
} queue_t;

struct lq *msg_queue_list;
unsigned int msg_queue_list_size = 0;

void prepare_curl_handle(char *new_msg)
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
/* if logfile is set, log there instead of stderr.
 * this is generally useful in combination with the below curl_verbose option,
 * since grabbing stderr from a running plugin may be difficult.
 */
	if (config.curl_logfile != NULL) {
		curl_logfile = fopen(config.curl_logfile, "ab");
		if (curl_logfile == NULL) {
			syslog(LOG_ERR, "could not open debug curl logfile %s", config.curl_logfile);
		} else {
			curl_easy_setopt(easy_h, CURLOPT_STDERR, curl_logfile);
		}
	}
	curl_easy_setopt(easy_h, CURLOPT_VERBOSE, config.curl_verbose);
	curl_easy_setopt(easy_h, CURLOPT_TIMEOUT_MS, MAX_CURL_GLOBAL_TIMEOUT);
	curl_easy_setopt(easy_h, CURLOPT_SSL_VERIFYHOST, config.ssl_verify);
	curl_easy_setopt(easy_h, CURLOPT_SSL_VERIFYPEER, config.ssl_verify);
	curl_easy_setopt(easy_h, CURLOPT_CAINFO, config.curl_cainfo);
	curl_easy_setopt(easy_h, CURLOPT_COPYPOSTFIELDS, new_msg);
}

/* Insert/remove new messages in the queue
 */
int list_check_queue()
{
	queue_t *prev;

	if (!msg_queue_list) {
		return 1;
	}

	prev = msg_queue_list;
	msg_queue_list = msg_queue_list->next;

	curl_multi_remove_handle(multi_h, easy_h);
	if (prev) {
		prepare_curl_handle(prev->msg);
		free(prev);
		msg_queue_list_size--;
		curl_multi_add_handle(multi_h, easy_h);
	}
	return 0;
}

/* select and fetch urls */
void curl_perform(void)
{
	/* Do we have curl enabled?
	 * If not, just bail here
	 */
	if (config.file_log != NULL) {
		return;
	}
	int msgs_left;
	int maxfd = -1;
	long http_code = 0;
	struct timeval timeout;
	int rc;
	CURLMsg *msg;
	CURLcode ret;
	fd_set r, w, e;

	/* Cleanup completed handles */
	while ((msg = curl_multi_info_read(multi_h, &msgs_left))) {
		if (msg->msg == CURLMSG_DONE) {
			ret = curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);
			if (ret != CURLM_OK) {
			   syslog(LOG_ERR, "Couldn't send JSON message (message is lost): %s.", curl_easy_strerror(ret));
			}
			if (http_code > HTTP_CODE_OK) {
				syslog(LOG_ERR, "Couldn't send JSON message (message is lost):  HTTP error code %ld.", http_code);
			}
		}
	}

	/* cURL will set this to 0 when there is no transfer left to process,
	 * signaling we can sent the next message. list_check_queue() will insert the next message from the queue
	 * into the multi_h.
	 * If there's no message in the queue, we bail for now.
	 */
	if (curl_nr_h == 0) {
		curl_nr_h = -1;
		if (list_check_queue()) {
			return;
		}
	}

	FD_ZERO(&r);
	FD_ZERO(&w);
	FD_ZERO(&e);

	/* With cURL you get the timeout you have to wait back from the library, so we use that for the select() call */
	ret = curl_multi_timeout(multi_h, &curl_timeout);
	if (ret != CURLM_OK) {
		syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000;
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
			/* This also sets curl_nr_h to exactly 0 if all the handles have been processed. */
			while ((ret = curl_multi_perform(multi_h, &curl_nr_h)) && (ret == CURLM_CALL_MULTI_PERFORM)) {
				continue;
			}
			if (ret != CURLM_OK) {
				syslog(LOG_ERR, "%s", curl_multi_strerror(ret));
			}
			break;
	}
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

static void int_handler(int sig)
{
	if (sig_stop == 1) {
		fprintf(stderr, "Repeated keyboard interrupt signal, forcing unclean program termination.\n");
		exit(127);
	}

	sig_stop = 1;
}

static void term_handler(int sig)
{
	sig_stop = 1;
}

static void hup_handler(int sig)
{
	sig_hup = 1;
}

static void reload_config(void)
{
	sig_hup = 0;
}

#ifdef REORDER_HACK
/*
 * Hack to reorder input
 * libaudit's auparse seems not to correlate messages correctly if event ids are out of sequence, ex (event id are
 * 418143181 and 418143182):
 * type=EXECVE msg=audit(1418253698.016:418143181): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=EXECVE msg=audit(1418253698.016:418143182): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143181):  cwd="/opt/observium"
 * type=CWD msg=audit(1418253698.016:418143182):  cwd="/opt/observium"
 *
 * This hack sort them back so that event ids are back to back like this:
 * type=EXECVE msg=audit(1418253698.016:418143181): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143181):  cwd="/opt/observium"
 * type=EXECVE msg=audit(1418253698.016:418143182): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143182):  cwd="/opt/observium"
 *
 * Without the hack, when the event id correlation fails, auparse would only return the parsed event until the point of
 * failure (so basically half of the message will be missing from the event/fields will be empty...)
 *
 * WARNING: The hack relies on properly null terminated strings here and there and doesn't do much bound checking other
 * than that. Be careful.
 * NOTE: This hack is only necessary when you can't fix libaudit easily, obviously. It's neither nice neither all that fast.
 */

/* count occurences of c in *in */
unsigned int strcharc(char *in, char c)
{
	unsigned int i = 0;

	for (i = 0; in[i]; in[i] == c ? i++ : *in++);
	return i;
}

static int eventcmp(const void *p1, const void *p2)
{
	char *s1, *s2;
	char *a1, *a2;
	int i;
	s1 = *(char * const*)p1;
	s2 = *(char * const*)p2;

	if (!s1 || !s2)
		return 0;

	a1 = s1;
	i = 0;
	while (a1[0] != ':' && a1[0] != '\0' && i < MAX_AUDIT_MESSAGE_LENGTH) {
		i++;
		a1++;
	}

	a2 = s2;
	i = 0;
	while (a2[0] != ':' && a2[0] != '\0' && i < MAX_AUDIT_MESSAGE_LENGTH) {
		i++;
		a2++;
	}

	return strcmp(a1, a2);
}

size_t reorder_input_hack(char **sorted_tmp, char *tmp)
{
		unsigned int lines = 0;
		unsigned int llen = 0;
		size_t flen = 0;
		unsigned int i = 0;
		lines = strcharc(tmp, '\n');

		char *buf[lines];
		char *line;
		char *saved;

		line = strtok_r(tmp, "\n", &saved);
		if (!line) {
			syslog(LOG_ERR, "message has no LF, message lost!");
			return 0;
		}

		llen = strnlen(line, MAX_AUDIT_MESSAGE_LENGTH);
		buf[i] = malloc(llen + 1);
		if (!buf[i]) {
			*sorted_tmp = tmp;
			syslog(LOG_ERR, "reorder_input_hack() malloc failed won't reorder");
			return strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH);
		}
		snprintf(buf[i], llen+1, "%s", line);
		i++;

		for (i; i < lines; i++) {
			line = strtok_r(NULL, "\n", &saved);
			if (!line) {
				continue;
			}
			llen = strnlen(line, MAX_AUDIT_MESSAGE_LENGTH);
			buf[i] = malloc(llen + 1);
			if (!buf[i]) {
				syslog(LOG_ERR, "reorder_input_hack() malloc failed partially reordering");
				continue;
			}
			snprintf(buf[i], llen+1, "%s", line);
		}

		qsort(&buf, lines, sizeof(char *), eventcmp);

		for (i = 0; i < lines; i++) {
			flen += snprintf(*sorted_tmp+flen, MAX_AUDIT_MESSAGE_LENGTH, "%s\n",  buf[i]);
			if (buf[i]) {
				free(buf[i]);
			}
		}
		return flen;
}
#endif

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	int len=0;
	struct sigaction sa;
	struct hostent *ht;
	char nodename[64];

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return 1;
	sa.sa_handler = int_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return 1;
	sa.sa_handler = hup_handler;
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		return 1;

	if (load_config(&config, CONFIG_FILE))
		if (load_config(&config, CONFIG_FILE_LOCAL))
			return 1;

	openlog(PROGRAM_NAME, LOG_CONS, LOG_DAEMON);

	if (gethostname(nodename, sizeof(nodename)-1)) {
		snprintf(nodename, 10, "localhost");
	}
	nodename[sizeof(nodename)] = '\0';
	ht = gethostbyname(nodename);
	if (ht == NULL) {
		hostname = strdup("localhost");
		if (hostname == NULL)
			return 1;
		syslog(LOG_ALERT,
			"gethostbyname could not find machine hostname, please fix this. Using %s as fallback. Error: %s",
			hostname, hstrerror(h_errno));
	} else {
		hostname = strdup(ht->h_name);
		if (hostname == NULL)
			return 1;
	}

	if (config.file_log != NULL) {
		file_log = fopen(config.file_log, "ab");
		if (file_log == NULL) {
			syslog(LOG_ERR, "failed to open %s", config.file_log);
			return -1;
		}
	}

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
	if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
		syslog(LOG_ERR, "curl_global_init() failed");
		return -1;
	}

	easy_h = curl_easy_init();
	multi_h = curl_multi_init();
	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Content-Type:application/json");
	if (!(easy_h && multi_h && slist1)) {
		syslog(LOG_ERR, "cURL handles creation failed, this is fatal");
		return -1;
	}

#ifdef REORDER_HACK
	int start = 0;
	int stop = 0;
	int i = 0;
	char *full_str_tmp = malloc(NR_LINES_BUFFERED*MAX_AUDIT_MESSAGE_LENGTH);
	char *sorted_tmp = malloc(NR_LINES_BUFFERED*MAX_AUDIT_MESSAGE_LENGTH);
	if (!sorted_tmp || !full_str_tmp) {
		syslog(LOG_ERR, "main() malloc failed for sorted_tmp || full_str_tmp, this is fatal");
		return -1;
	}
	sorted_tmp[0] = '\0';
	full_str_tmp[0] = '\0';
#endif

	auparse_add_callback(au, handle_event, NULL, NULL);
	syslog(LOG_INFO, "%s loaded\n", PROGRAM_NAME);

	/* At this point we're initialized so we'll read stdin until closed and feed the data to auparse, which in turn will
	 * call our callback (handle_event) every time it finds a new complete message to parse.
	 */
	do {
		/* NOTE: There's quite a few reasons for auparse_feed() from libaudit to fail parsing silently so we have to be careful here.
		 * Anything passed to it:
		 * - must have the same timestamp for a given event id. (kernel takes care of that, if not, you're out of luck).
		 * - must always be LF+NULL terminated ("\n\0"). (fgets takes care of that even thus it's not nearly as fast as fread).
		 * - must always have event ids in sequential order. (REORDER_HACK takes care of that, it also buffer lines, since, well, it needs to).
		 */
		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin)) {
			if (sig_hup)
				reload_config();
			if (sig_stop)
				break;

			len = strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH);
#ifdef REORDER_HACK
			if (strncmp(tmp, "type=EOE", 8) == 0) {
				stop++;
			} else if (strncmp(tmp, "type=SYSCALL", 12) == 0) {
				start++;
			}
			if (i > NR_LINES_BUFFERED || start != stop) {
				strncat(full_str_tmp, tmp, len);
				i++;
			} else {
				strncat(full_str_tmp, tmp, len);
				len = reorder_input_hack(&sorted_tmp, full_str_tmp);
				auparse_feed(au, sorted_tmp, len);
				i = 0;
				start = stop = 0;
				sorted_tmp[0] = '\0';
				full_str_tmp[0] = '\0';
			}
#else
			auparse_feed(au, tmp, len);
#endif
			curl_perform();
		}

		if (feof(stdin))
			break;
	} while (sig_stop == 0);

	auparse_flush_feed(au);

	while (msg_queue_list)
		curl_perform();

	auparse_destroy(au);
	curl_easy_cleanup(easy_h);
	curl_multi_cleanup(multi_h);
	curl_global_cleanup();
	if (curl_logfile)
		fclose(curl_logfile);
	if (file_log)
		fclose(file_log);
	free_config(&config);
	free(hostname);
#ifdef REORDER_HACK
	free(sorted_tmp);
#endif
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

/* Removes quotes
 * Remove  CR and LF
 * @const char *in: if NULL, no processing is done.
 */
char *unescape(const char *in)
{
	if (in == NULL)
		return NULL;

	char *dst = (char *)in;
	char *s = dst;
	char *src = (char *)in;
	char c;

	while ((c = *src++) != '\0') {
		if ((c == '"') || (c == '\n') || (c == '\r') || (c == '\t')
				|| (c == '\b') || (c == '\f') || (c == '\\'))
			continue;
		*dst++ = c;
	}
	*dst++ = '\0';
	return s;
}

/* Add a field to the json msg's details={}
 * @attr_t *list: the attribute list to extend
 * @const char *st: the attribute name to add
 * @const char *val: the attribut value - if NULL, we won't add the field to the json message at all.
 */
attr_t *_json_add_attr(attr_t *list, const char *st, char *val, int freeme)
{
	attr_t *new;

	if (st == NULL || !strncmp(st, "(null)", 6) || val == NULL || !strncmp(val, "(null)", 6)) {
		return list;
	}

	new = malloc(sizeof(attr_t));
	if (!new) {
		syslog(LOG_ERR, "json_add_attr() malloc failed attribute will be empty: %s", st);
		return list;
	}
	snprintf(new->value, MAX_ATTR_SIZE, "\t\t\"%s\": \"%s\"", st, unescape(val));
	new->next = list;

	if (freeme) {
		free(val);
	}

	return new;
}

/* Convenience wrappers for _json_add_attr */
attr_t *json_add_attr_free(attr_t *list, const char *st, char *val)
{
	return _json_add_attr(list, st, val, 1);
}

attr_t *json_add_attr(attr_t *list, const char *st, const char *val)
{
	return _json_add_attr(list, st, (char *)val, 0);
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

/* Resolve uid to username - returns malloc'd value */
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
	if (!buf) {
		return NULL;
	}

	if (uid == -1) {
		return NULL;
	}
	if (getpwuid_r(uid, &pwd, buf, bufsize, &result) != 0) {
		return NULL;
	}
	if (result == NULL) {
		return NULL;
	}
	name = strdup(pwd.pw_name);
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

/* This creates the JSON message we'll send over by deserializing the C struct into a char array
 * the function name is rather historical, since this does not send to syslog anymore.
 */
void syslog_json_msg(struct json_msg_type json_msg)
{
	attr_t *head = json_msg.details;
	attr_t *prev;
	queue_t *new_q;
	int len;

	if (msg_queue_list_size > MAX_CURL_QUEUE_SIZE) {
		syslog(LOG_WARNING, "syslog_json_msg() MAX_CURL_QUEUE_SIZE of %u reached, message lost!", MAX_CURL_QUEUE_SIZE);
		return;
	}

	new_q = malloc(sizeof(queue_t));
	if (!new_q) {
		syslog(LOG_ERR, "syslog_json_msg() new_q malloc() failed, message lost!");
		return;
	}

	len = snprintf(new_q->msg, MAX_JSON_MSG_SIZE,
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
		PROGRAM_NAME, json_msg.timestamp, PROGRAM_NAME, STR(PROGRAM_VERSION));

	while (head) {
			len += snprintf(new_q->msg+len, MAX_JSON_MSG_SIZE-len, "\n%s,", head->value);
			prev = head;
			head = head->next;
			free(prev);

			if (head == NULL) {
				new_q->msg[len-1] = '\n';
			}
	}

	len += snprintf(new_q->msg+len, MAX_JSON_MSG_SIZE-len, "	}\n}\n");
	new_q->msg[MAX_JSON_MSG_SIZE-1] = '\0';

	/* If using curl, fill up the queue, else just print to file */
	if (config.file_log == NULL) {
		new_q->next = msg_queue_list;
		msg_queue_list = new_q;
		msg_queue_list_size++;
	} else {
		if (fputs(new_q->msg, file_log) < 0) {
			/* Retry once (file closed?) */
			file_log = fopen(config.file_log, "ab");
			if (file_log == NULL || fputs(new_q->msg, file_log) < 0) {
				syslog(LOG_ERR, "could not log to file %s", config.file_log);
			}
		}
		free(new_q);
	}
}

/* The main event handling, parsing function */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num=0;


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

	typedef enum {
		CAT_EXECVE,
		CAT_READ,
		CAT_WRITE,
		CAT_PTRACE,
		CAT_ATTR,
		CAT_APPARMOR,
		CAT_CHMOD,
		CAT_CHOWN,
		CAT_PROMISC,
		CAT_TIME,
		CAT_SOCKET,
		CAT_LISTEN
	} category_t;
	category_t category;

	const char *cwd = NULL, *argc = NULL, *cmd = NULL;
	const char *path = NULL;
	const char *dev = NULL;
	const char *sys;
	const char *syscall = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	char serial[64] = "\0";
	time_t t;
	struct tm *tmp;

	char f[8];
	int len, tmplen;
	int argcount, i;
	int promisc;
	int havejson = 0;

	/* wait until the lib gives up a full/ready event */
	if (cb_event_type != AUPARSE_CB_EVENT_READY) {
		return;
	}

	json_msg.timestamp = (char *)alloca(TS_LEN);
	json_msg.summary = (char *)alloca(MAX_SUMMARY_LEN);
	if (!json_msg.summary || !json_msg.timestamp) {
		syslog(LOG_ERR, "handle_event() alloca failed, message lost!");
		return;
	}

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		if (!type)
			continue;

		if (!auparse_first_field(au))
			continue;

		t = auparse_get_time(au);
		tmp = localtime(&t);
		strftime(json_msg.timestamp, TS_LEN, "%FT%T%z", tmp);
		snprintf(serial, TS_LEN-1, "%lu", auparse_get_serial(au));
		json_msg.details = json_add_attr(json_msg.details, "auditserial", serial);

		switch (type) {
			case AUDIT_ANOM_PROMISCUOUS:
				dev = auparse_find_field(au, "dev");
				if (!dev)
					return;

				havejson = 1;
				category = CAT_PROMISC;

				json_msg.details = json_add_attr(json_msg.details, "dev", dev);
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "promiscious", auparse_find_field(au, "prom"));
				promisc = auparse_get_field_int(au);
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "old_promicious", auparse_find_field(au, "old_prom"));
				goto_record_type(au, type);
				if (auparse_find_field(au, "auid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "originaluser",
														get_username(auparse_get_field_int(au)));

					json_msg.details = json_add_attr(json_msg.details, "originaluid",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "user", get_username(auparse_get_field_int(au)));
					json_msg.details = json_add_attr(json_msg.details, "uid", auparse_get_field_str(au));
				}
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "gid", auparse_find_field(au, "gid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "session", auparse_find_field(au, "ses"));
				goto_record_type(au, type);
				break;

			case AUDIT_AVC:
				argc = auparse_find_field(au, "apparmor");
				if (!argc)
					return;

				havejson = 1;
				category = CAT_APPARMOR;

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
					json_msg.details = json_add_attr(json_msg.details, "processname",
														get_proc_name(auparse_get_field_int(au)));
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
				path = auparse_find_field(au, "name");
				json_msg.details = json_add_attr(json_msg.details, "path", path);
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
					syslog(LOG_DEBUG, "System call %u is not supported by %s", i, PROGRAM_NAME);
					json_del_attrs(json_msg.details);
					return;
				}

				json_msg.details = json_add_attr(json_msg.details, "processname", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				if (!strncmp(sys, "write", 5) || !strncmp(sys, "unlink", 6) || !strncmp(sys,
							"rename", 6)) {
					havejson = 1;
					category = CAT_WRITE;
				} else if (!strncmp(sys, "read", 4) || !strncmp(sys, "open", 4) || !strncmp(sys, "link", 4) ||
						!strncmp(sys, "mmap", 4) || !strncmp(sys, "mmap2", 5) || !strncmp(sys, "sendfile", 8) ||
						!strncmp(sys, "sendfile64", 10)) {
					havejson = 1;
					category = CAT_READ;
				} else if (!strncmp(sys, "setxattr", 8)) {
					havejson = 1;
					category = CAT_ATTR;
				} else if (!strncmp(sys, "chmod", 5) || !strncmp(sys, "fchmodat", 8)) {
					havejson = 1;
					category = CAT_CHMOD;
				} else if (!strncmp(sys, "chown", 5) || !strncmp(sys, "fchown", 6)) {
					havejson = 1;
					category = CAT_CHOWN;
				} else if (!strncmp(sys, "ptrace",  6)) {
					havejson = 1;
					category = CAT_PTRACE;
				} else if (!strncmp(sys, "execve", 6)) {
					havejson = 1;
					category = CAT_EXECVE;
				} else if (!strncmp(sys, "ioctl", 5)) {
					category = CAT_PROMISC;
				} else if (!strncmp(sys, "adjtimex", 8)) {
					havejson = 1;
					category = CAT_TIME;
				} else if (!strncmp(sys, "socket", 6)) {
					havejson = 1;
					category = CAT_SOCKET;
					json_msg.details = json_add_attr(json_msg.details, "addr_family", auparse_find_field(au, "a0"));
					json_msg.details = json_add_attr(json_msg.details, "sock_type", auparse_find_field(au, "a1"));
				} else if (!strncmp(sys, "listen", 6)) {
					havejson = 1;
					category = CAT_LISTEN;
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
					json_msg.details = json_add_attr_free(json_msg.details, "originaluser",
														get_username(auparse_get_field_int(au)));

					json_msg.details = json_add_attr(json_msg.details, "originaluid",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "user", get_username(auparse_get_field_int(au)));
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

	/* We set the category/summary here as the JSON msg structure is complete at this point. (i.e. just before
	 * syslog_json_msg...) Since we don't know the order of messages, this is the only way to ensure we can fill a
	 * useful summary from various AUDIT messages (sometimes the values are set from AUDIT_EXECVE, sometimes AUDIT_PATH,
	 * and so on.
	 */

	if (category == CAT_EXECVE) {
#ifdef IGNORE_EMPTY_EXECVE_COMMAND
		/* Didn't get a type=EXECVE message? Then fullcmd will be empty.
		 * This happens when executing scripts for example:
		 * /usr/local/bin/test.sh => exec
		 * => exec /bin/bash
		 * => kernel sends execve syscall for the bash exec without an EXECVE message but a path set to:
		 * dirname(script_path)/exec_name (e.g.: /usr/local/bin/bash in example above).
		 * then fork again for the "real" command (e.g.: /bin/bash /local/bin/test.sh).
		 * While it's correct we only really care for that last command (which has an EXECVE type)
		 * Thus we're skipping the messages without EXECVE altogether, they're mostly noise for our purposes.
		 * It's a little wasteful as we have to free the attributes we've allocated, but as messages can be out of order..
		 * .. we don't really have a choice.
		 */
		if (strlen(fullcmd) == 0) {
			attr_t *head = json_msg.details;
			attr_t *prev;

			while (head) {
				prev = head;
				head = head->next;
				free(prev);
			}
			return;
		}
#endif
		json_msg.category = "execve";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Execve: %s",
					unescape(fullcmd));
	} else if (category == CAT_WRITE) {
		json_msg.category = "write";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Write: %s",
					unescape(path));
	} else if (category == CAT_ATTR) {
		json_msg.category = "attribute";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Attribute: %s",
					unescape(path));
	} else if (category == CAT_CHMOD) {
		json_msg.category = "chmod";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Chmod: %s",
					unescape(path));
	} else if (category == CAT_CHOWN) {
		json_msg.category = "chown";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Chown: %s",
					unescape(path));
	} else if (category == CAT_PTRACE) {
		json_msg.category = "ptrace";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Ptrace");
	} else if (category == CAT_TIME) {
		json_msg.category = "time";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"time has been modified");
	} else if (category == CAT_PROMISC) {
		json_msg.category = "promiscuous";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Promisc: Interface %s set promiscous %s",
					unescape(dev), promisc ? "on": "off");
	}

	/* syslog_json_msg() also frees json_msg.details when called. */
	syslog_json_msg(json_msg);
	curl_perform();
}
