

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb/cascade# nmap -Pn -sV -n 10.10.10.182
    Nmap scan report for 10.10.10.182
    Host is up (0.030s latency).
    Not shown: 986 filtered ports
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-07 12:04:33Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    49154/tcp open  msrpc         Microsoft Windows RPC
    49155/tcp open  msrpc         Microsoft Windows RPC
    49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49158/tcp open  msrpc         Microsoft Windows RPC
    49165/tcp open  msrpc         Microsoft Windows RPC
    Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows


2.

root@nidus:/opt/impacket/examples# rpcclient -U "" 10.10.10.182
Enter WORKGROUP\'s password:
  rpcclient $> enumdomusers
    user:[CascGuest] rid:[0x1f5]
    user:[arksvc] rid:[0x452]
    user:[s.smith] rid:[0x453]
    user:[r.thompson] rid:[0x455]
    user:[util] rid:[0x457]
    user:[j.wakefield] rid:[0x45c]
    user:[s.hickson] rid:[0x461]
    user:[j.goodhand] rid:[0x462]
    user:[a.turnbull] rid:[0x464]
    user:[e.crowe] rid:[0x467]
    user:[b.hanson] rid:[0x468]
    user:[d.burman] rid:[0x469]
    user:[BackupSvc] rid:[0x46a]
    user:[j.allen] rid:[0x46e]
    user:[i.croft] rid:[0x46f]



root@nidus:/opt/impacket/examples# enum4linux -a 10.10.10.182

  =============================
  |    Users on 10.10.10.182    |
  =============================
  index: 0xee0 RID: 0x464 acb: 0x00000214 Account: a.turnbull	Name: Adrian Turnbull	Desc: (null)
  index: 0xebc RID: 0x452 acb: 0x00000210 Account: arksvc	Name: ArkSvc	Desc: (null)
  index: 0xee4 RID: 0x468 acb: 0x00000211 Account: b.hanson	Name: Ben Hanson	Desc: (null)
  index: 0xee7 RID: 0x46a acb: 0x00000210 Account: BackupSvc	Name: BackupSvc	Desc: (null)
  index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: CascGuest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
  index: 0xee5 RID: 0x469 acb: 0x00000210 Account: d.burman	Name: David Burman	Desc: (null)
  index: 0xee3 RID: 0x467 acb: 0x00000211 Account: e.crowe	Name: Edward Crowe	Desc: (null)
  index: 0xeec RID: 0x46f acb: 0x00000211 Account: i.croft	Name: Ian Croft	Desc: (null)
  index: 0xeeb RID: 0x46e acb: 0x00000210 Account: j.allen	Name: Joseph Allen	Desc: (null)
  index: 0xede RID: 0x462 acb: 0x00000210 Account: j.goodhand	Name: John Goodhand	Desc: (null)
  index: 0xed7 RID: 0x45c acb: 0x00000210 Account: j.wakefield	Name: James Wakefield	Desc: (null)
  index: 0xeca RID: 0x455 acb: 0x00000210 Account: r.thompson	Name: Ryan Thompson	Desc: (null)
  index: 0xedd RID: 0x461 acb: 0x00000210 Account: s.hickson	Name: Stephanie Hickson	Desc: (null)
  index: 0xebd RID: 0x453 acb: 0x00000210 Account: s.smith	Name: Steve Smith	Desc: (null)
  index: 0xed2 RID: 0x457 acb: 0x00000210 Account: util	Name: Util	Desc: (null)



  ==============================
  |    Groups on 10.10.10.182    |
  ==============================


  [+] Getting builtin group memberships:
    Group 'Guests' (RID: 546) has member: CASCADE\CascGuest

  [+] Getting local group memberships:
    Group 'Remote Management Users' (RID: 1126) has member: CASCADE\arksvc
    Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith
    Group 'HR' (RID: 1115) has member: CASCADE\s.hickson
    Group 'IT' (RID: 1113) has member: CASCADE\arksvc
    Group 'IT' (RID: 1113) has member: CASCADE\s.smith
    Group 'IT' (RID: 1113) has member: CASCADE\r.thompson
    Group 'Audit Share' (RID: 1137) has member: CASCADE\s.smith
    Group 'AD Recycle Bin' (RID: 1119) has member: CASCADE\arksvc
    Group 'Data Share' (RID: 1138) has member: CASCADE\Domain Users


root@nidus:/opt/impacket/examples# ldapsearch -h 10.10.10.182 -p 389 -x -s base
  ..
  namingContexts: DC=cascade,DC=local
  namingContexts: CN=Configuration,DC=cascade,DC=local
  namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
  namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
  namingContexts: DC=ForestDnsZones,DC=cascade,DC=local
  defaultNamingContext: DC=cascade,DC=local
  schemaNamingContext: CN=Schema,CN=Configuration,DC=cascade,DC=local
  configurationNamingContext: CN=Configuration,DC=cascade,DC=local
  rootDomainNamingContext: DC=cascade,DC=local


root@nidus:/opt/impacket/examples# ldapsearch -h 10.10.10.182 -p 389 -x -b "DC=cascade,DC=local"



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1.



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

ldapsearch:
  https://tylersguides.com/guides/search-active-directory-ldapsearch/
