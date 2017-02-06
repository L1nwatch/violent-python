# 第 3 章 用 Python 进行取证调查

## 你曾经去过哪里？——在注册表中分析无线访问热点

Windows 注册表是一个分层式的数据库，其中存储了操作系统的配置设置信息。

从 `Windows Vista` 起，注册表在 `HKLM\SOFT_WARE\Microsoft\Windows NT\CurrentVersion\Network-List\Signatures\Unmanaged` 子键中就会存储所有的网络信息。在 Windows 命令行提示符中，我们能列出每个网络显示出 `profile Guid` 对网络的描述、网络名和网关的 MAC 地址。

```shell
C:\Windows\system32\reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged" /s HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Unmanaged\010103000F0000F008000000F0000F04BCC2360E4B8F7DC8BDAFAB8AE....

ProfileGuid	REG_SZ	...
Description	REG_SZ	...
```

### 使用 WinReg 读取 Windows 注册表中的内容

注册表中把网关 MAC 地址存为 `REG_BINARY` 类型的。形如：`00115024687F0000`，其实就是地址 `00:11:50:24:68:7F`，下面这个函数可以实现转换：

```python
def val2addr(val):
    addr = str()
    for ch in val:
        addr += "%02x " % ord(ch)
    addr = addr.strp(" ").replace(" ", ":")[0:17]
    return addr
```

接下来要从 Windows 注册表指定的键值中提取各个被列出来的网络名称和 MAC 地址。需要使用 `_winreg` 库，这是 Python 的 Windows 版安装程序默认会安装的一个库。

```python
from _winreg import *
def print_nets():
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)
    print("[*] Networks You have Joined.")
    for i in range(100):
        try:
            guid = EnumKey(key, i)
            net_key = OpenKey(key, str(guid))
            n, addr, t = EnumValue(net_key, 5)
            n, name, t = EnumValue(net_key, 4)
            mac_addr = val2addr(addr)
            net_name = str(name)
            print("[+] {} {}".format(net_name, mac_addr))
            CloseKey(net_key)
        except:
            break
```

确保在拥有管理员权限的命令行窗口中运行，就可以读取注册表中的键值

### 使用 Mechanize 把 MAC 地址传给 Wigle

知道了无线访问热点的 MAC 地址之后，可以把访问热点的物理位置也打印出来。许多数据库中，都有海量的把无线访问热点与它们所在的物理位置相对应起来的列表。

[SkyHook 数据库](http://www.skyhookwireless.com)提供了一个根据 Wi-Fi 的位置获取地理位置信息的软件开发包。Ian McCracken 开发的一个[开源项目](http://code.google.com/p/maclocate/)让我们能访问这个数据库。还有 Google、微软等都有 Wi-Fi 地址位置数据库。

数据库，也是[开源项目](wigle.net)仍然允许用户根据无线访问热点的 MAC 地址得到它所在的物理位置。通过网页查询某个无线 SSID MAC 地址对应的物理位置，并收集响应页面。其中返回结果 `maplat=47.25264359&maplon=-87.25624084` 表示的就是无线访问热点的经度和纬度。

需要使用 `mechanize` 库，它允许 Python 编写带状态的 Web 程序。也就是说在正确地登陆 Wigle 服务器后，它会保存和重用登陆认证 cookie。

```python
import mechanize, urllib, re, urlparse
def wigle_print(username, password, netid):
    browser = mechanize.Browser()
    browser.open("http://wigle.net")
    req_data = urllib.urlencode({"credential_0": username, "credential_1": password})
    
    browser.open("https://wigle.net/gps/gps/main/login", req_data)
    params = {}
    params["netid"] = netid
    req_params = urllib.urlencode(params)
    resp_url = "http://wigle.net/gps/gps/main/confirmquery/"
    resp = browser.open(resp_url, req_params).read()
    map_lat = "N/A"
    map_lon = "N/A"
    r_lat = re.findall(r"maplat=.*\&", resp)
    if r_lat:
        map_lat = r_lat[0].split("&")[0].split("=")[1]
    r_lon = re.findall(r"maplon=.*\&", resp)
    if r_lon:
        map_lon = r_lon[0].split()
    print("[-] Lat: {}, Lon: {}".format(map_lat, map_lon))
```

## 用 Python 恢复被删入回收站中的内容

