#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.02.01 按照书里给的代码, 依旧跑不了, 因为是 ssh 的...
"""
import optparse
import pexpect.pxssh as pxssh

__author__ = '__L1n__w@tch'

bot_net = list()


class Client:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.connect()

    def connect(self):
        try:
            s = pxssh.pxssh()
            s.login(self.host, self.user, self.password)
            return s
        except Exception as e:
            print(e)
            print("[-] Error Connecting")

    def send_command(self, cmd):
        self.session.sendline(cmd)
        self.session.prompt()
        return self.session.before


def bot_net_command(command):
    for client in bot_net:
        output = client.send_command(command)
        print("[*] Output from {}".format(client.host))
        print("[+] {}".format(output))


def add_client(host, user, password):
    client = Client(host, user, password)
    bot_net.append(client)


if __name__ == "__main__":
    add_client("10.10.10.110", "root", "toor")
    add_client("10.10.10.120", "root", "toor")
    add_client("10.10.10.130", "root", "toor")
    bot_net_command("uname -v")
    bot_net_command("cat /etc/issue")
