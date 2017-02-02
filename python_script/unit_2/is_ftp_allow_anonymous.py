#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.02.02 判断一个 FTP 服务器是否允许匿名访问
"""
import ftplib

__author__ = '__L1n__w@tch'


def anon_login(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login("test", "test")
        print("[*] {} FTP Anonymous Logon Succeeded.".format(host))
        ftp.quit()
        return True
    except Exception as e:
        print("[-] {} FTP Anonymous Logon Failed.".format(host))
        return False


def return_default(ftp):
    dir_list = list()

    try:
        dir_list = ftp.nlst()
    except Exception as e:
        print(e)
        print("[-] Could not list directory contents.")
        print("[-] Skipping To Next Target.")
        return

    ret_list = list()
    for file_name in dir_list:
        fn = file_name.lower()
        if ".php" in fn or ".htm" in fn or ".asp" in fn:
            print("[+] Found default page: {}".format(file_name))
            ret_list.append(file_name)
    return ret_list


if __name__ == "__main__":
    host = "192.168.158.161"
    anon_login(host)

    test_ftp = ftplib.FTP(host)
    test_ftp.login("test", "test")
    return_default(test_ftp)
    test_ftp.close()
