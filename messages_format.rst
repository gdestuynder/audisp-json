===============
Messages format
===============

This document details the message format for audisp-json, and lists the possible
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
Audisp-json is one of the plugins.

As audisp-json receives several syscall messages for a single event (like "write
to a file" or "execute a program"), it correlates on the message info, id and
aggregates all relevant information for a single event into a single message.

That message is then transformed to MozDef JSON format with a type, such as "EXECVE" or
"WRITE" and send to syslog.

Format example
--------------

.. code::

    {
        "category": "EXECVE",
            "details": {
                "uid": 0,
                "gid": 0,
                "euid": 0,
                "fsuid": 0,
                "egid": 0,
                "suid": 0,
                "ouid": "(null)",
                "ogid": "(null)",
                "rdev": "(null"),
                "sessionid": 20239,
                "ppid": 29929,
                "dev": "(null)",
                "mode": "(null)",
                "cwd": "/home/kang",
                "username": "root",
                "auditedusername": "kang",
                "auid": 1000,
                "inode": 283892,
                "parentprocess": "sudo",
                "process": "/bin/cat",
                "filename": "(null)",
                "auditkey": "exe",
                "tty": "/dev/pts/0"
            },
            "hostname": "blah.private.scl3.mozilla.com",
            "processid": 14619,
            "processname": "audisp-json",
            "severity": "INFO",
            "summary": "sudo cat /etc/passwd",
            "tags": [
                "linux audit",
                ],
            "timestamp": "2014-03-18T23:20:31.013344+00:00"
    }

Implemented message categories
------------------------------

:WRITE: writes to a file, 'w' in audit.rules.
:ATTR: change file attributes/metadata, 'a' in audit.rules.
:CHMOD: change file mode, 'chmod' syscall in audit.rules.
:CHOWN: change file owner, 'chown' syscall in audit.rules.
:PTRACE: process trace, gdb/strace do that for example, 'ptrace' syscall in audit.rules.
:EXECVE: execute program, 'execve' syscall in audit.rules.
:AVC_APPARMOR: AppArmor messages, generally used on Ubuntu. Not handled by audit.rules.
