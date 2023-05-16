#!/usr/bin/env python3
from PySide2.QtCore import *
import time

def genPassword(i):
    length = 32
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
    try:
        qsrand(i)
        password = ''
        for i in range(length):
            idx = qrand() % len(charset)
            nchar = charset[idx]
            password += str(nchar)
    except:
        print("Something went wrong..")
    return(password)


def main():
    start = time.time()
    storage = []
    i = 1
    try: 
        with open("pw-list.txt", "w") as a_file:
            for i in range(1000):
            #while len(storage) < 1000:
                passwd = genPassword(i)
                print("loop nr.", i, "- generated passwords:", len(storage))
                i = i + 1
                
                if passwd not in storage:
                    storage.append(passwd)
                    a_file.write(passwd + '\n')

    except KeyboardInterrupt:
        print("Stopping..")
    end = time.time()
    print("time elapsed:", end - start, "seconds")


if __name__ == "__main__":
    main()
