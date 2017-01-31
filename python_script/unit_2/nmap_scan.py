#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.01.31 按照书中给的代码示例, 使用 nmap 进行扫描操作
"""
import nmap
import optparse

__author__ = '__L1n__w@tch'


def nmap_scan(target_host, target_port):
    nm_scan = nmap.PortScanner()
    nm_scan.scan(target_host, target_port)
    state = nm_scan[target_host]["tcp"][int(target_port)]["state"]
    print("[*] {} tcp/{} {}".format(target_host, target_port, state))


def main():
    parser = optparse.OptionParser("usage %prog -H <target host> -p <target port>")

    parser.add_option("-H", dest="target_host", type=str, help="specify target host")
    parser.add_option("-p", dest="target_port", type=str, help="specify target port[s] separated by comma")

    options, args = parser.parse_args()

    target_host = options.target_host
    target_ports = str(options.target_port).split(", ")

    if target_host is None or target_ports is None:
        print(parser.usage)
        exit(-1)

    for target_port in target_ports:
        nmap_scan(target_host, target_port)


if __name__ == "__main__":
    main()
