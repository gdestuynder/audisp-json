# Copyright (c) 2014 Mozilla Corporation.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Guillaume Destuynder <gdestuynder@mozilla.com>

CFLAGS	:= -fPIE -DPIE -g -D_REENTRANT -D_GNU_SOURCE
LDFLAGS	:= -pie -Wl,-z,relro
LIBS	:= -lauparse -laudit `curl-config --libs`

GCC		:= gcc
LIBTOOL	:= libtool
INSTALL	:= install

DESTDIR	:= /
PREFIX	:= /usr

VERSION	:= 1.4

all: audisp-json

audisp-json: json-config.o audisp-json.o
	${LIBTOOL} --tag=CC --mode=link gcc ${CFLAGS} ${LDFLAGS} ${LIBS} -o audisp-json json-config.o audisp-json.o

json-config.o: json-config.c
	${GCC} -I. ${CFLAGS} ${LIBS} -c -o json-config.o json-config.c

audisp-json.o: audisp-json.c
	${GCC} -I. ${CFLAGS} ${LIBS} -c -o audisp-json.o audisp-json.c

install: audisp-json au-json.conf audisp-json.conf
	${INSTALL} -D -m 0644 au-json.conf ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/au-json.conf
	${INSTALL} -D -m 0644 audisp-json.conf ${DESTDIR}/${PREFIX}/etc/audisp/audisp-json.conf
	${INSTALL} -D -m 0755 audisp-json ${DESTDIR}/${PREFIX}/sbin/audisp-json

uninstall:
	rm -f ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/au-json.conf
	rm -f ${DESTDIR}/${PREFIX}/etc/audisp/audisp-json.conf
	rm -f ${DESTDIR}/${PREFIX}/sbin/audisp-json

packaging: audisp-json au-json.conf audisp-json.conf
	${INSTALL} -D -m 0644 au-json.conf tmp/etc/audisp/plugins.d/au-json.conf
	${INSTALL} -D -m 0644 audisp-json.conf tmp/etc/audisp/audisp-json.conf
	${INSTALL} -D -m 0755 audisp-json tmp/sbin/audisp-json

rpm: packaging
	fpm -C tmp -v ${VERSION} -n audisp-json --license GPL --vendor mozilla --description "json plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-json -d audit-libs -d libcurl \
		--config-files etc/audisp/plugins.d/au-json.conf --config-files etc/audisp/audisp-json.conf -s dir -t rpm .
# Bonus options
#		--rpm-digest sha512 --rpm-sign

deb: packaging
	fpm -C tmp -v ${VERSION} -n audisp-json --license GPL --vendor mozilla --description "json plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-json -d auditd -d libcurl \
		--deb-build-depends libaudit-dev --deb-build-depends libcurl-dev \
		--config-files etc/audisp/plugins.d/au-json.conf --config-files etc/audisp/audisp-json.conf -s dir -t deb .

clean:
	rm -f audisp-json
	rm -fr *.o
	rm -fr tmp
	rm -rf *.rpm
	rm -rf *.deb
