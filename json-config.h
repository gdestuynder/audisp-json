/* json-config.h
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * Copyright 2014 Mozilla Corporation
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

#ifndef AUDISP_JSON_CONFIG_H
#define AUDISP_JSON_CONFIG_H

typedef struct json_conf
{
	const char *mozdef_url;
	const char *curl_cainfo;
	const char *curl_logfile;
	int ssl_verify;
	int curl_verbose;
} json_conf_t;

void clear_config(json_conf_t *config);
int  load_config(json_conf_t *config, const char *file);
void free_config(json_conf_t *config);

#endif
