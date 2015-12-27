/* json-config.c -- 
 * Copyright (c) 2014 Mozilla Corporation.
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 *   Guillaume Destuynder <gdestuynder@mozilla.com>
 * 
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "json-config.h"

struct nv_pair
{
	const char *name;
	const char *value;
	const char *option;
};

struct kw_pair 
{
	const char *name;
	int (*parser)(struct nv_pair *, int, json_conf_t *);
	int max_options;
};

struct nv_list
{
	const char *name;
	int option;
};

static char *get_line(FILE *f, char *buf);
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int server_parser(struct nv_pair *nv, int line,
		json_conf_t *config);
static int curl_ca_parser(struct nv_pair *nv, int line,
		json_conf_t *config);
static int ssl_parser(struct nv_pair *nv, int line,
		json_conf_t *config);
static int curl_parser(struct nv_pair *nv, int line,
		json_conf_t *config);
static int curl_fparser(struct nv_pair *nv, int line,
		json_conf_t *config);

static const struct kw_pair keywords[] =
{
	{"mozdef_url",	server_parser,	0},
	{"curl_cainfo", curl_ca_parser,	0},
	{"ssl_verify",	ssl_parser,	0},
	{"curl_verbose", curl_parser,	0},
	{"curl_logfile", curl_fparser,	0},
	{NULL}
};

/*
 * Set everything to its default value
*/
void clear_config(json_conf_t *config)
{
	config->mozdef_url = NULL;
	config->ssl_verify = 1;
}

int load_config(json_conf_t *config, const char *file)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[128];

	clear_config(config);

	/* open the file */
	mode = O_RDONLY;
	rc = open(file, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening %s (%s)", file,
				strerror(errno));
			return 1;
		}
		syslog(LOG_WARNING,
			"Config file %s doesn't exist", file);
		return 1;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable", 
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file", 
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "r");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				syslog(LOG_ERR, 
				"Wrong number of arguments for line %d in %s", 
					lineno, file);
				break;
			case 2: // no '=' sign
				syslog(LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, file);
				break;
			default: // something else went wrong... 
				syslog(LOG_ERR, 
					"Unknown error for line %d in %s", 
					lineno, file);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			syslog(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			syslog(LOG_ERR, 
				"Keyword \"%s\" has invalid option "
				"\"%s\" in line %d of %s", 
				nv.name, nv.option, lineno, file);
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, config);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}

		lineno++;
	}

	fclose(f);
	return 0;
}

static char *get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, 128, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
	}
	return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
	ptr = strtok(buf, " ");
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = strtok(NULL, " ");
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = strtok(NULL, " ");
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* See if there's an option */
	ptr = strtok(NULL, " ");
	if (ptr) {
		nv->option = ptr;

		/* Make sure there's nothing else */
		ptr = strtok(NULL, " ");
		if (ptr)
			return 1;
	}

	/* Everything is OK */
	return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}

static int server_parser(struct nv_pair *nv, int line, 
		json_conf_t *config)
{
	if (nv->value)
		config->mozdef_url = strdup(nv->value);
	else
		config->mozdef_url = NULL;
	return 0;
}

static int ssl_parser(struct nv_pair *nv, int line,
		json_conf_t *config)
{
	config->ssl_verify = 1;
	if (nv->value) {
		if (strncasecmp(nv->value, "no", 2) == 0) {
			config->ssl_verify = 0;
		}
	}

	return 0;
}

static int curl_ca_parser(struct nv_pair *nv, int line,
		json_conf_t *config)
{
	if (nv->value)
		config->curl_cainfo = strdup(nv->value);
	else
		config->curl_cainfo = NULL;
	return 0;
}

static int curl_parser(struct nv_pair *nv, int line,
		json_conf_t *config)
{
	config->curl_verbose = 2;
	if (nv->value) {
		if (strncasecmp(nv->value, "no", 2) == 0) {
			config->curl_verbose = 0;
		}
	}

	return 0;
}

static int curl_fparser(struct nv_pair *nv, int line,
		json_conf_t *config)
{
	if (nv->value)
		config->curl_logfile = strdup(nv->value);
	else
		config->curl_logfile = NULL;
	return 0;
}

void free_config(json_conf_t *config)
{
	free((void *)config->mozdef_url);
}

