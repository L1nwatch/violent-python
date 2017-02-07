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

在使用 FAT 文件系统的 Windows 98 及之前的 Windows 系统中，回收站目录是 `C:\Recycled\`。在包括 Windows NT/2000 和 Windows XP 在内的支持 NTFS 的操作系统中，回收站是 `C:\Recycler\目录`。在 Windows Vista 和 Windows 7 中，回收站目录则是 `C:\$Recycle.Bin`

### 使用 OS 模块寻找被删除的文件/文件夹

依次测试各个文件夹即可，不是判断操作系统再来找对应文件夹

```python
import os
def return_dir():
    dirs = ["c:/Recycler/", "c:/Recycled/", "C:/$Recycle.Bin/"]
    for recycle_dir in dirs:
        if os.path.isdir(recycle_dir):
            return recycle_dir
    return None
```

在找到回收站目录之后，就要去检查其中的内容。其中有两个子目录，都含有字符串 `S-1-5-21-1275210071-1715567821-725345543-`，并分别以 1005 或 500 结尾。这个字符串表示的是用户的 SID，它对应的是机器里一个唯一的用户帐户

### 用 Python 把 SID 和用户名关联起来

可以用 Windows 注册表把 SID 转换成一个准确的用户名。检查的是注册表键 `HKEY_LOCAL_MACHINE\SOFT-WARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath`，看到返回的是 `%SystemDrive%\Documents and Settings\<USERID>` 值。通过 `reg query` 命令，可以直接把 SID 转成用户名

```shell
C:\RECYCLER>reg query "HKEY_LOCAL...." /v ProfileImagePath
```

通过 Python 实现，打开注册表检查 ProfileImagePath 键，提取出其中存放的值，并返回位于用户路径中最后一个反斜杠之后的用户名

```python
from _winreg import *
def sid2user(sid):
    try:
        key = OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}".format(sid))
        value, type = QueryValueEx(key, "ProfileImagePath")
        user = value.split("\\")[-1]
        return user
    except:
        return sid
```

## 元数据

作为一种文件里非明显可见的对象，元数据可以存在于文档、电子表格、图片、音频和视频文件中。创建这些文件的应用程序可能会把文档的作者、创建和修改时间、可能的更新版本和注释这类详细信息存储下来。

### 使用 PyPDF 解析 PDF 文件中的元数据

PyPDF 允许提取文档中的内容，或对文档进行分割、合并、复制、加密和解密操作。若要提取元数据，可以使用 `.getDocumentInfo()` 方法，该方法会返回一个 tuple 数组，每个 tuple 中都含有对元数据元素的一个描述及它的值。逐一遍历这个数组，就能打印出 PDF 文档的所有元数据。

```python
import pyPdf
from pyPdf import PdfFileReader
def print_meta(file_name):
    pdf_file = PdfFileReader(file(file_name, "rb"))
    doc_info = pdf_file.getDocumentInfo()
    print("[*] PDF MetaData For: {}".format(file_name))
    for meta_item in doc_info:
        print("[+] {}:{}".format(meta_item, doc_info[meta_item]))
```

### 理解 Exif 元数据

Exif（exchange image file format，交换图像文件格式）标准定义了如何存储图像和音频文件的标准。

Exif 标准中含有多个对取证调查非常有用的标签（tag），工具 `exiftool` 用它可以解析这些标签。

### 用 BeautifulSoup 下载图片

BeautifulSoup 允许我们快速解析 HTML 和 XML 文档

实现查找所有 img 标签并下载：

```python
import urllib2
from bs4 import BeautifuleSoup
from urlparser import urlsplit
from os.path import basename

def find_images(url):
    print("[+] Finding images on {}".format(url))
    url_content = urllib2.urlopen(url).read()
    soup = BeautifulSoup(url_content)
    img_tags = soup.findAll("img")
    return img_tags

def download_image(img_tag):
    try:
        print("[+] Downloading image...")
        img_src = img_tag["src"]
        img_content = urllib2.urlopen(img_src).read()
        img_file_name = basename(urlsplit(img_src)[2])
        img_file = open(img_file_name, "wb")
        img_file.write(img_content)
        img_file.close()
        return img_file_name
    except:
        return ""
```

### 用 Python 的图像处理库读取图片中的 Exif 元数据

利用 PIL 库提取 GPS 元数据：

```python
from PIL import Image
from PIL.ExifTags import  TAGS

def test_for_exif(image_file_name):
    try:
        exif_data = {}
        img_file = Image.open(image_file_name)
        info = img_file._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                exif_data[decoded] = value
            exif_gps = exif_data["GPSINFO"]
            if exif_gps:
                print("[*] {} contains GPS MetaData".format(img_file_name))
    except:
        pass
```

## 用 Python 分析应用程序的使用记录

### 理解 Skype 中的 SQLite3 数据库

在 Windows 系统中，Skype 在 `C:\Documents and Settings\<User>\ApplicationData\Skype\<Skype-account>` 目录中存储了一个名为 `main.db` 的数据库。在 macOS 系统中，这个数据库的存储路径为 `/Users/<User>/Library/Application Support/Skype/<Skype-account>`

连接 SQLite3 数据库后 `SELECT tbl_name FROM sqlite_master WHERE type=='table'`，SQLite 数据库维护一张名为 `sqlite_master` 的表，这张表中含有一个名为 `tbl_name` 的列，其中描述了数据库中的各张表。

Accounts 表记录了使用该应用程序的用户账户的相关信息，其中的各列记录了用户名、Skype 的昵称、用户的位置和创建该账户的日期等信息。

数据库是以 UNIX 时间格式存储账户创建时间的，SQL 方法 `datetime()` 可以把这个值转换成更方便阅读的格式

### 使用 Python 和 SQLite3 自动查询 Skype 的数据库

```python
import sqlite3
def print_profile(skype_db):
    conn = sqlite3.connect(skype_db)
    c = conn.cursor()
    c.execute("SELECT fullname, skypename, city, country, datetime(profile_timestamp, 'unixepoch') FROM Accounts;")
    for row in c:
        print("[*] -- Found Account --")
        print("[+] User: {}".format(row[0]))
        print("[+] Skype Username: {}".format(row[1]))
        print("[+] Location: {},{}".format(row[2], row[3]))
        print("[+] Profile Date: {}".format(row[4]))
```

多表处理：

```python
def print_call_log(skype_db):
    conn = sqlite3.connect(skype_db)
    c = conn.cursor()
    c.execute("SELECT datetime(begin_timestamp, 'unixepoch'), identity FROM calls, conversations WHERE calls.conv_dbid = conversations.id;")
    print("[*] -- Found Calls --")
    for row in c:
        print("[+] Time: {} | partner: {}".format(row[0], row[1]))
```

Skype 的数据库会把所有发送和收到的消息都保存在数据库中。数据库中把这些信息存放在一张名为 `Messages` 的表中。从这张表中用 SELECT 语句选出 timestamp、`dialog_partner`、author 和 `body_xml`。注意，如果 `dialog_partner` 和 author 字段是不一样的，那么就是数据库的所有者发送这条消息给 `dialog_partner` 的。反之，如果 `dialog_partner` 和 author 字段是一样的，就是 `dialog_partner` 发送的这条消息，这时需要在消息前加一个 `from`

```python
def print_messages(skype_db):
    conn = sqlite3.connect(skype_db)
    c = conn.cursor()
    c.execute("SELECT datetime(timestamp, 'unixepoch'), dialog_partner, author, body_xml FROM Messages;")
    print("[*] -- Found Messages --")
    for row in c:
        try:
            if "partlist" not in str(row[3]):
                if str(row[1]) != str(row[2]):
                    msg_direction = "To {}: ".format(row[1])
        	else:
            	msg_direction = "From {}: ".format(row[2])
            print("Time: {} {} {}".format(row[0], msg_direction, row[3]))
        except:
            pass
```

### 其他有用的一些 Skype 查询语句

只想打印出联系人列表中其生日不为空的联系人：

```sql
SELECT fullname, birthday FROM contacts WHERE birthday > 0;	
```

只想输出 conversation 表中只与某个特定的 `<SKYPE-PARTNER>` 相关的通话记录：

```sql
SELECT datetime(timestamp, 'unixepoch'), dialog_partner, author, body_xml, FROM Messages WHERE dialog_partner='<SKYPE-PARTNER>'
```

要删除 conversation 表中只与某个特定的 `<SKYPE-PARTNER>` 相关的通话记录

```sql
DELETE FROM messages WHERE skypename='<SKYPE-PARTNER>'
```

### 用 Python 解析火狐浏览器的 SQLite3 数据库

在 Windows 操作系统中，火狐把这些数据库存放在 `"C:/Documents and Settings/<USER>/Application Data/Mozilla/Firefox/Profiles/<profile folder>/"` 目录中，在 macOS 系统中，火狐把这些数据库存放在 `"/Users/<USER>/Library/Application Support/Firefox/Profiles/<profile folder>"` 目录中

文件 `downloads.sqlite` 数据库时火狐用户下载文件的相关信息。其中只有一张名为 `moz_downloads` 的表记录了文件名、源下载地址、下载时间、文件大小、引用（referrer）和本地存放该文件的路径。

```python
import sqlite3
def print_downloads(download_db):
    conn = sqlite3.connect(download_db)
    c = conn.cursor()
    c.execute("SELECT name, source, datetime(endTime/1000000, 'unixepoch') FROM moz_downloads;")
    print("[*] --- Files Downloaded ---")
    for row in c:
        print("[+] File: {} from source: {} at: {}".format(row[0], row[1], row[2]))
```

数据库 `moz_cookies` 表中保存的是 cookie 相关的数据。

```python
def print_cookies(cookies_db):
    try:
        conn = sqlite3.connect(cookie_db)
        c = conn.cursor()
        c.execute("SELECT host, name, value FROM moz_cookies")
        print("[*] --- Found Cookies ---")
        for row in c:
            host = row[0]
            name = row[1]
            value = row[2]
            print("[+] Host: {}, Cookie: {}, Value: {}".format(host, name, value))
    except Exception as e:
        if "encrypted" in str(e):
            print("[*] Error reading your cookies database.")
            print("[*] Upgrade your Python-Sqlite3 Library")
```

上网历史记录保存在 `places.sqlite` 的数据库中，其中的 `moz_places` 表可以给出关于用户在何时（时间）访问了何处（地址）的网站信息。ForensicWiki 网站上建议使用 `moz_places` 和 `moz_historyvisits` 表中的数据，以获取一张真正的浏览器上网历史记录。

```sql
SELECT url, datetime(visit_date/1000000, 'unixepoch') FROM moz_places, moz_historyvisits WHERE visit_count > 0 AND moz_places.id == moz_historyvisits.place_id;
```

### 用 Python 调查 iTunes 的手机备份

苹果的 iOS 操作系统实际上会跟踪和记录设备的 GPS 经纬度信息，并把它们存储在 `consolidated.db` 的数据库中。其中有一张名为 `Cell-Location` 的表，其中含有手机已经收集到的 GPS 定位点。在备份移动设备时，记录到计算机的移动设备的副本也含有这一信息。尽管 iOS 操作系统设计的功能会删除这些地理位置信息，但调查发现这些数据仍然存在。

当用户对 iPhone/iPad 设备进行备份时，它会把相关文件存放到计算机中一个特定的目录中。在 Windows 操作系统中，iTunes 应用程序会把数据存放在用户目录下的移动设备备份目录中（`C:/Documents and Settings/<USERNAME>/Application Data/AppleComputer/MobileSync/Backup`），而在 macOS 中，这个目录则是 `/Users/<USERNAME>/Library/Application Support/MobileSync/Backup/`。对移动设备进行备份的 iTunes 程序会把所有的设备备份文件都存放在这个目录中。

为了获取关于文件的信息，用 UNIX 命令 `file` 来分析各个文件的文件类型。可以看到移动设备备份目录中有一些 SQLite3 数据库文件、JPEG 图片文件、纯二进制文件和 ASCII 文本文件

可以用脚本快速列举出在整个移动设备备份目录中每一个数据库中所有表的表名：

```sql
SELECT tbl_name FROM sqlite_master WHERE type=="table"
```

每个 SQLite 数据库中都会维护一张名为 `sqlite_master` 的表，其中含有整个数据库结构的信息，记录了整个数据库中各张表的结构。

含有 `message` 表的库即为文本消息数据库，可以把发送时间、对方手机号码以及消息本身打印出来：

```sql
SELECT datetime(date, 'unixepoch'), address, text FROM message WHERE address > 0;
```