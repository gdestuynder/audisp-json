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
LIBS	:= -lauparse -laudit

GCC		:= gcc
LIBTOOL	:= libtool
INSTALL	:= install

DESTDIR	:= /
PREFIX	:= /usr

VERSION	:= 1.1

all: audisp-cef

audisp-cef: cef-config.o audisp-cef.o
	${LIBTOOL} --tag=CC --mode=link gcc ${CFLAGS} ${LDFLAGS} ${LIBS} -o audisp-cef cef-config.o audisp-cef.o

cef-config.o: cef-config.c
	${GCC} -I. ${CFLAGS} ${LIBS} -c -o cef-config.o cef-config.c

audisp-cef.o: audisp-cef.c
	${GCC} -I. ${CFLAGS} ${LIBS} -c -o audisp-cef.o audisp-cef.c

install: audisp-cef au-cef.conf audisp-cef.conf
	${INSTALL} -D -m 0644 au-cef.conf ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/au-cef.conf
	${INSTALL} -D -m 0644 audisp-cef.conf ${DESTDIR}/${PREFIX}/etc/audisp/audisp-cef.conf
	${INSTALL} -D -m 0755 audisp-cef ${DESTDIR}/${PREFIX}/sbin/audisp-cef

uninstall:
	rm -f ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/au-cef.conf
	rm -f ${DESTDIR}/${PREFIX}/etc/audisp/audisp-cef.conf
	rm -f ${DESTDIR}/${PREFIX}/sbin/audisp-cef

packaging: audisp-cef au-cef.conf audisp-cef.conf
	${INSTALL} -D -m 0644 au-cef.conf tmp/etc/audisp/plugins.d/au-cef.conf
	${INSTALL} -D -m 0644 audisp-cef.conf tmp/etc/audisp/audisp-cef.conf
	${INSTALL} -D -m 0755 audisp-cef tmp/sbin/audisp-cef

rpm: packaging
	fpm -C tmp -v ${VERSION} -n audisp-cef --license GPL --vendor mozilla --description "CEF plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-cef -d audit-libs \
		--config-files etc/audisp/plugins.d/au-cef.conf --config-files etc/audisp/audisp-cef.conf -s dir -t rpm .
# Bonus options
#		--rpm-digest sha512 --rpm-sign

deb: packaging
	fpm -C tmp -v ${VERSION} -n audisp-cef --license GPL --vendor mozilla --description "CEF plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-cef -d libaudit0 --deb-build-depends libaudit-dev \
		--config-files etc/audisp/plugins.d/au-cef.conf --config-files etc/audisp/audisp-cef.conf -s dir -t deb .

clean:
	rm -f audisp-cef
	rm -fr *.o
	rm -fr tmp
	rm -rf *.rpm
	rm -rf *.deb
