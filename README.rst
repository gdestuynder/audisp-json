==========
Audisp-json
==========

.. contents:: Table of contents

This program is a plugin for Linux Audit user space programs available at <http://people.redhat.com/sgrubb/audit/>.
It uses the audisp multiplexer.

Audisp-json correlates messages coming from the kernel's audit (and through audisp) into a single JSON message that is
sent directly to a log server (it doesn't use syslog).
The JSON format used is MozDef message format.

Regular audit log messages and audisp-json error, info messages still use syslog.


Due to the ring buffer filling up when the front-end HTTP server does not process fast enough, the program may slowly
grow in memory for a while on busy systems. It'll stop at 512 messages (hard-coded) buffered.

Diagram
-------

  ::

  +-----------+            +------------+
  |           |   Netlink  |            |
  |  kernel   +------------>   auditd   |
  |           |            |            |
  +-----------+            +------+-----+
                                  |                +------------+             +--------------+
                           pipe   |                |            |   HTTP(S)   |              |
                                  |         +------> audisp-json+------------>+  MozDef JSON |
                           +------v-----+   |      |            |             |              |
                           |            |   |      +------------+             +--------------+
                           | audispd    +---+
                           |            |  pipe
                           +---------+--+          +------------+
                                     |             |            |
                                     +-------------> Other      |
                                           pipe    | plugins    |
                                                   +------------+

Building
--------

Required dependencies:
- Audit (2.0+)
- libtool
- libcurl

For package building:
- FPM
- rpmbuild (rpm)

Build targets:
=============
They're self explanatory.

- make
- make rpm
- make deb
- make install
- make uninstall
- make clean

Mozilla build targets
=====================
We previously used audisp-cef, so we would want to mark that package as obsolete.

- make rpm FPMOPTS="--replaces audisp-cef"
- make deb FPMOPTS="--replaces audisp-cef"

Static compilation tips
=======================
If you need to compile in statically compiled libraries, here are the variables to change from the makefile,
using libcurl and openssl statically compiled as an example.

 ::

    @@ -48,9 +48,11 @@ else ifeq ($(DEBUG),1)
    else
    CFLAGS  := -fPIE -DPIE -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2
    endif
    +CFLAGS := -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2

    -LDFLAGS        := -pie -Wl,-z,relro
    -LIBS   := -lauparse -laudit `curl-config --libs`
    +#LDFLAGS       := -pie -Wl,-z,relro -static
    +LDFLAGS := -static -ldl -lz -lrt
    +LIBS   := -lauparse -laudit $(pkg-config --static --libs libssl libcurl)
    ./path-to-libcurl/lib/.libs/libcurl.a ./path-to-openssl/libssl.a
    ./path-to-openssl/libcrypto.a
    DEFINES        := -DPROGRAM_VERSION\=${VERSION} ${REORDER_HACKF} ${IGNORE_EMPTY_EXECVE_COMMANDF}

    GCC            := gcc

Deal with auditd quirks, or how to make auditd useable in prod
--------------------------------------------------------------

These examples filter out messages that may clutter your log or/and DOS yourself (high I/O) if auditd goes
down for any reason.

Example for rsyslog
===================

 ::

    #Drop native audit messages from the kernel (may happen is auditd dies, and may kill the system otherwise)
    :msg, regex, "type=[0-9]* audit" ~
    #Drop audit sid msg (work-around until RH fixes the kernel - should be fixed in RHEL7 and recent RHEL6)
    :msg, contains, "error converting sid to string" ~


Example for syslog-ng
=====================

 ::

    source s_syslog { unix-dgram("/dev/log"); };
    filter f_not_auditd { not message("type=[0-9]* audit") or not message("error converting sid to string"); };
    log{ source(s_syslog);f ilter(f_not_auditd); destination(d_logserver); };

Misc other things to do
=======================

- It is suggested to bump the audispd queue to adjust for extremely busy systems, for ex. q_depth=512.
- You will also probably need to bump the kernel-side buffer and change the rate limit in audit.rules, for ex. -b 16384
  -r 500.

Message handling
----------------

Syscalls are interpreted by audisp-json and transformed into a MozDef JSON message.
This means, for example, all execve() and related calls will be aggregated into a message of type EXECVE.

.. note: MozDef messages are not sent to syslog. They're sent to MozDef directly.

Supported messages are listed in the document messages_format.rst

Configuration file
==================

The audisp-json.conf file has 4 options:

:mozdef_url: Any server supporting JSON MozDef messages
:ssl_verify: Yes or no. Only use no for testing purposes.
:curl_verbose: Enables curl verbose mode for debugging. start audisp-json in the foreground to see messages.
:curl_logfile: Path to a file to log curl debug messages to. Most useful with curl_verbose also set. Otherwise, message
               go to stderr.
:curl_cainfo: Specify the path to a single CA certificate, if needed. When not specified, system's CA bundle is used.

The audit configuration itself is up to you, but you get you started we have included the a base configurable file that
provides self-auditing and execve (think "bash history on steroids") auditing, see 'example_audit.rules'.

The au-json.conf file configures audispd, which will start the audisp-json plugin.
