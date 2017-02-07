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

