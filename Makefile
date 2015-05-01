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

VERSION	:= 1.10

#FPM options, suggestions:
# --replaces audisp-cef
# --rpm-digest sha512 --rpm-sign
FPMOPTS :=

# Turn this on if you get issues with out of sequence messages/missing event attributes
# Only needed for some versions of libaudit - if you don't have problems, leave off.
REORDER_HACK := 0
ifneq ($(REORDER_HACK),0)
	REORDER_HACKF	:= -DREORDER_HACK
endif

# Turn this off if you want the extra noise of script execs and the like, which do not produce an EXECVE audit message
# See the source code for more info.
IGNORE_EMPTY_EXECVE_COMMAND := 1
ifneq ($(IGNORE_EMPTY_EXECVE_COMMAND),0)
	IGNORE_EMPTY_EXECVE_COMMANDF	:= -DIGNORE_EMPTY_EXECVE_COMMAND
endif

DEBUG	:= 0
ifeq ($(DEBUG),2)
	DEBUGF	:= -DDEBUG
	CFLAGS	:= -fPIE -DPIE -g -O0 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all 
else ifeq ($(DEBUG),1)
	CFLAGS	:= -fPIE -DPIE -g -O0 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all 
else
	CFLAGS	:= -fPIE -DPIE -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2
endif

LDFLAGS	:= -pie -Wl,-z,relro
LIBS	:= -lauparse -laudit `curl-config --libs`
DEFINES	:= -DPROGRAM_VERSION\=${VERSION} ${REORDER_HACKF} ${IGNORE_EMPTY_EXECVE_COMMANDF}

GCC		:= gcc
LIBTOOL	:= libtool
INSTALL	:= install

DESTDIR	:= /
PREFIX	:= /usr

all: audisp-json

audisp-json: json-config.o audisp-json.o
	${LIBTOOL} --tag=CC --mode=link gcc ${CFLAGS} ${LDFLAGS} ${LIBS} -o audisp-json json-config.o audisp-json.o

json-config.o: json-config.c
	${GCC} -I. ${CFLAGS} ${LIBS} -c -o json-config.o json-config.c

audisp-json.o: audisp-json.c
	${GCC} -I. ${CFLAGS} ${DEBUGF} ${LIBS} ${DEFINES} -c -o audisp-json.o audisp-json.c

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
	fpm ${FPMOPTS} -C tmp -v ${VERSION} -n audisp-json --license GPL --vendor mozilla --description "json plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-json -d audit-libs -d libcurl \
		--config-files etc/audisp/plugins.d/au-json.conf --config-files etc/audisp/audisp-json.conf -s dir -t rpm .

deb: packaging
	fpm ${FPMOPTS} -C tmp -v ${VERSION} -n audisp-json --license GPL --vendor mozilla --description "json plugin for Linux Audit" \
		--url https://github.com/gdestuynder/audisp-json -d auditd -d libcurl3 \
		--deb-build-depends libaudit-dev --deb-build-depends libcurl4-openssl-dev \
		--config-files etc/audisp/plugins.d/au-json.conf --config-files etc/audisp/audisp-json.conf -s dir -t deb .

clean:
	rm -f audisp-json
	rm -fr *.o
	rm -fr tmp
	rm -rf *.rpm
	rm -rf *.deb
