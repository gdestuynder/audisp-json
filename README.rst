==========
Audisp-cef
==========

.. contents:: Table of contents

This program is a plugin for Linux Audit user space programs available at <http://people.redhat.com/sgrubb/audit/>.
It uses the audisp multiplexer.

Audisp-cef correlates messages coming from the kernel's audit (and through audisp) into a single CEF message through syslog.
CEF stands for Common Event Format.

Building
--------

Required dependencies:
- Audit (2.0+)
- libtool

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

Deal with auditd quirks, or how to make auditd useable in prod
--------------------------------------------------------------

We're assuming you're logging auditd stuff to LOCAL5 here. Replace <SYSLOG_SERVER_IP_HERE> by your syslogger.
Due to the nature/sensitivity of the logs, using TLS as transport is highly recommended.

These examples filter out messages that may kill your log if auditd goes down for any reason, or general
messages which you may want to forward but to keep in their own faciilty, or simply not log to disk, for
useability reasons.

Example for rsyslog
===================

 ::

    #Drop native audit messages from the kernel (may happen is auditd dies, and may kill the system otherwise)
    :msg, regex, "type=[0-9]* audit" ~
    #Sent audit rate limit errors directly to the remote syslog server
    :msg, contains, "rate limit exceeded" @<SYSLOG_SERVER_IP_HERE>
    :msg, contains, "audit_lost=" @<SYSLOG_SERVER_IP_HERE>
    #Drop audit sid msg (work-around until RH fixes the kernel - should be fixed in RHEL7 and recent RHEL6)
    :msg, contains, "error converting sid to string" ~

    #Don't log auditd messages to disk, we're logging way too much stuff for that
    *.info;local5.none			/var/log/messages
    #Log remotely instead
    local5.*					@<SYSLOG_SERVER_IP_HERE>

Example for syslog-ng
=====================

 ::

    source s_syslog { unix-dgram("/dev/log"); };
    filter f_auditd { message("type=[0-9]* audit") and message("rate limit exceeded") and message("audit_lost=") and facility(local5); };
    destination d_logserver { udp("<SYSLOG_SERVER_IP_HERE>" port(514)); };
    log{ source(s_syslog); filter(f_auditd); destination(d_logserver); };
    # If you want to "not log" auditd messages, negate the same filter to your other log items
    
Message handling
----------------

Syscalls are interpreted by audisp-cef and transformed into a CEF message which has a new attribute.
This means, for example, all execve() and related calls will be aggregated into a message of type EXECVE.

Supported messages are listed in the document messages_format.rst
