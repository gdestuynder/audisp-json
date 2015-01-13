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

.. note::

        Values such as "mode": "(null)" are omitted by audisp-json to reduce the message size.
        Only fields with actual values are sent/displayed.

.. note::

        All "details" field values are string in order to deal with document indexing issues when the type changes
        between int and str for example (instead it's always str).

.. code::

    {
        "category": "EXECVE",
            "details": {
                "auditserial": "2939394",
                "uid": "0",
                "gid": "0",
                "euid": "0",
                "fsuid": "0",
                "egid": "0",
                "suid": "0",
                "sessionid": "20239",
                "ppid": "29929",
                "cwd": "/home/kang",
                "username": "root",
                "auditedusername": "kang",
                "auid": "1000",
                "inode": "283892",
                "parentprocess": "sudo",
                "process": "/bin/cat",
                "auditkey": "exe",
                "tty": "/dev/pts/0"
            },
            "hostname": "blah.private.scl3.mozilla.com",
            "processid": 14619,
            "processname": "audisp-json",
            "severity": "INFO",
            "summary": "Execve: sudo cat /etc/passwd",
            "tags": [
                "linux audit",
                ],
            "timestamp": "2014-03-18T23:20:31.013344+00:00"
    }

Fields reference
----------------
.. note:: Integer fields are of type uint32_t (i.e. bigger than regular signed int) even when stored as str. This means 4,294,967,295 is a valid value and does not represent -2,147,483,648.

.. note:: See also 'man 8 auditctl' and/or https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sec-Understanding_Audit_Log_Files.html

:category: Type of message (such as execve, write, chmod, etc.).
:processid: PID of the process generating the messages (audisp-json's PID)
:processname: Process name of the process generating the messages (audisp-json).
:hostname: System FQDN as seen get gethostbyname().
:severity: Syslog-style severity level.
:summary: Human readable summary of the message.
:tags: Various tags to indicate the audisp-json plugin version.
:timestamp: UTC timestamp, or with timezone set.
:details.auditserial: The message/event serial sent by audit. This is mainly used for debugging or as a reference between the Mozdef/JSON message and the host's original message.
:details.uid,gid: User/group id who started the program.
:details.username: Human readable alias of the uid.
:details.euid: Effective user/group id the program is running as.
:details.fsuid,fsgid: User/group id of the owner of the running program itself, on the filesystem.
:details.ouid,ouid: Owner user/group id on the filesystem.
:details.suid,sgid: Saved user/group id - used when changing uid sets within the program, but a uid/gid has been saved (i.e. the program can revert to the suid if it wants to).
:details.auid or details.originaluid: Auditd user id - the original user who logged in (always the same even after setuid - this is generally set by PAM).
:details.originaluser: Human readable alias of the auid/originaluid.
:details.rdev: Recorded device identifier (MAJOR:MINOR numbers) 
:details.rdev: Recorded device identifier for special files.
:details.mode: File mode on the filesystem (full numeral mode, such as 0100600 - that would be 0600 "short mode" or u+rw or -rw------).
:details.sessionid: Kernel session identifier for the user running the program. It's set at login.
:details.tty: If any TTY is attached, it's there - used by interactive shells usually (such as /dev/pts/0).
:details.auditkey: Custom identifier set by the person setting audit rules on the system.
:details.process: Program involved's full path.
:details.pid: PID of the program involved.
:details.inode: Node identifier on the filesystem for the program.
:details.cwd: Current working directory of the program.
:details.parentprocess: Name of the parent process which has spawned details.process.
:details.ppid: PID of the parent process.

Implemented message categories
------------------------------

:WRITE: writes to a file, 'w' in audit.rules.
:ATTR: change file attributes/metadata, 'a' in audit.rules.
:CHMOD: change file mode, 'chmod' syscall in audit.rules.
:CHOWN: change file owner, 'chown' syscall in audit.rules.
:PTRACE: process trace, gdb/strace do that for example, 'ptrace' syscall in audit.rules.
:EXECVE: execute program, 'execve' syscall in audit.rules.
:AVC_APPARMOR: AppArmor messages, generally used on Ubuntu. Not handled by audit.rules.
:ANOM_PROMISCUOUS: network interface promiscuous setting on/off. Handled by 'ioctl' syscall in audit.rules.
