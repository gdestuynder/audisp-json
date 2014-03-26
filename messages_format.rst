===============
Messages format
===============

This document details the message format for audisp-cef, and lists the possible
messages.

How, Why, What
--------------

kernel side and rules loading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The Linux kernel sends messages via the netlink protocol to a user space
daemon, auditd.  These messages depends on the audit configuration, which is
generally saved in /etc/audit/audit.rules.  The rules are loaded at audit
startup into the kernel and define which system calls should be logged and
under which conditions.
Some other kernel components, such as AVC, may also emit non-syscall related messages.

audisp plugins
~~~~~~~~~~~~~~
The messages that auditd receives are then passed to audispd which is a
multiplexer, sending back those messages to various plugins.
Audisp-cef is one of the plugins.

As audisp-cef receives several syscall messages for a single event (like "write
to a file" or "execute a program"), it correlates on the message info, id and
aggregates all relevant information for a single event into a single message.

That message is then transformed to CEF format with a type, such as "EXECVE" or
"WRITE" and send to syslog.

Format example
--------------

.. code::

    CEF:0|Unix|auditd|1|EXECVE|Unix Exec|Low|msg=gid=0  euid=0 suid=0 fsuid=0 egid=0
    sgid=0 fsgid=0 ses=20944 cwd=”/tmp” inode=00:00 [...] suser=toor
    dhost=random.stage.host.mozilla.com dst=10.22.1.100 dproc=/usr/bin/gcc fname=gcc
    cs1=gcc sploit.c -o test cs2=No cs3=exec cs4=pts2 cs5=sudo cs6=No cn1=1663

Implemented message types
-------------------------

:WRITE: writes to a file, 'w' in audit.rules.
:ATTR: change file attributes/metadata, 'a' in audit.rules.
:CHMOD: change file mode, 'chmod' syscall in audit.rules.
:CHOWN: change file owner, 'chown' syscall in audit.rules.
:PTRACE: process trace, gdb/strace do that for example, 'ptrace' syscall in audit.rules.
:EXECVE: execute program, 'execve' syscall in audit.rules.
:AVC_APPARMOR: AppArmor messages, generally used on Ubuntu. Not handled by audit.rules.
