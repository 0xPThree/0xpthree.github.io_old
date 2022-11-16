#!/usr/bin/env python3
# by 0xPThree - exploit.se
from colorama import Fore
import hashlib
import requests
import argparse
import time

r = requests.session()
storage = []

def getUrl(target, md5sum):
    # Send GET request
    url = target + md5sum + "/"
    req = r.get(url)
    if req.status_code == 200: #and len(req.text) != 0:
        print("Found something on:", url)
        storage.append(url)
        return
    else:
        return

def createMd5(id):
    md5sum = hashlib.md5(str(id).encode()).hexdigest()
    return(md5sum)
                                                                         

def main():
    start = time.time()
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=70)
    parser = argparse.ArgumentParser(formatter_class=formatter)
    parser.add_argument('-t','--target', type=str, help='target url')
    parser.add_argument('-s','--start', type=int, help='start id')
    parser.add_argument('-e','--end', type=int, help='end id')
    args = parser.parse_args()

    # Loop through start to end
    for i in range(args.start, args.end):
        print("Testing nr.", i)
        md5sum = createMd5(i)
        getUrl(args.target, md5sum)

    # Print all results stored in 'storage'
    if not storage:
        print("Nothing found..")
    else:
        for i in range(len(storage)):
            print("Results", i, "-", storage[i])

    end = time.time()
    print("time elapsed:", end - start, "seconds")

    
if __name__ == "__main__":
    main()
