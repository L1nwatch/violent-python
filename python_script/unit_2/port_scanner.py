#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.01.29 按照第 2 章编写一个端口扫描器
"""
import optparse
import socket

__author__ = '__L1n__w@tch'


def initialize():
    parser = optparse.OptionParser("usage %prog -H <target host> -p <target port>")

    parser.add_option("-H", dest="target_host", type=str, help="specify target host")
    parser.add_option("-p", dest="target_port", type=int, help="specify target port")

    options, args = parser.parse_args()

    target_host = options.target_host
    target_port = options.target_port

    if target_host is None or target_port is None:
        print(parser.usage)
        exit(-1)

    return target_host, target_port


def connect_scan(target_host, target_port):
    """
    TCP 全连接扫描
    :param target_host: 目标主机
    :param target_port: 目标端口
    :return:
    """
    try:
        conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_sock.connect((target_host, target_port))
        print("[+] {}/tcp open".format(target_port))

        conn_sock.send(b"Violent Python")
        results = conn_sock.recv(1024)
        print("[+] Get Response: {}".format(results))
        conn_sock.close()
    except socket.timeout:
        print("[-] {}/tcp closed or No Response".format(target_port))


def port_scan(target_host, target_ports):
    """
    执行端口扫描操作
    :param target_host: 目标主机
    :param target_ports: 目标端口列表
    :return:
    """
    try:
        target_ip = socket.gethostbyname(target_host)
    except RuntimeError:
        print("[-] Can not resolve {}: Unknown host".format(target_host))
        return

    try:
        target_name = socket.gethostbyaddr(target_ip)
        print("[+] Scan results for {}".format(target_name[0]))
    except RuntimeError:
        print("[+] Scan Results for {}".format(target_ip))

    socket.setdefaulttimeout(1)

    for target_port in target_ports:
        print("[*] Scanning port {}".format(target_port))
        connect_scan(target_host, target_port)


if __name__ == "__main__":
    host, port = initialize()
    port_scan(host, [port])
