# 第 6 章 用 Python 刺探网络

## 使用 Mechanize 库上网

Mechanize 中的主要类（Browser）允许我们对浏览器中的任何内容进行操作。

```python
import mechanize
def view_page(url):
    browser = mechanize.Browser()
    page = browser.open(url)
    source_code = page.read()
    print(source_code)
view_page("http://www.syngress.com/")
```

Mechanize 提供了状态化编程（stateful programming）和方便的 HTML 表单填写，便于解析和处理诸如 “HTTP-Equiv” 和刷新之类的命令。此外，它还自带了不少能让你保持匿名状态的函数。

### 匿名性——使用代理服务器、User-Agent 及 Cookie

网站有多种方法能够唯一标识网页的访问者。Web 服务器记录发起网页请求的 IP 是标识用户的第一种方式。Python 也可以连接代理服务器，这能给程序增加匿名性。Mechanize 的 Browser 类中有一个属性，即程序能用它指定一个代理服务器。MyCurdy 在 [http://rmccurdy.com/scripts/proxy/good.txt](http://rmccurdy.com/scripts/proxy/good.txt) 中维护着一个可用代理的列表。

```python
import mechanize
def test_proxy(url, proxy):
    browser = mechanize.Browser()
    browser.set_proxies(proxy)
    page = browser.open(url)
    source_code = page.read()
    print(source_code)
url = "http://ip.nefsc.noaa.gov/"
hide_me_proxy = {"http": "216.155.139.115:3128"}
test_proxy(url, hide_me_proxy)
```

浏览器现在有一层匿名性了，但网站还会使用浏览器提供的 `user-agent` 字符串作为唯一标识用户的另一种方法。在正常情况下，`user-agent` 字符串可以让网站获知用户使用的是哪种浏览器这一重要信息，同时这个字段还记录了内核版本、浏览器版本，以及其他一些关于用户的详细信息。恶意网站利用这些信息根据不同的浏览器版本发送不同的漏洞利用代码，而其他一些网站则利用这些信息区分那些躲在 NAT 后面的局域网里的永不。

Mechanize 能像添加代理那样，轻松修改 `user-agent`，[网站](http://www.useragentstring.com/pages/useragentstring.php) 提供了大量有效的 `user-agent` 字符串。

```python
import mechanize
def test_user_agent(url, user_agent):
    browser = mechanize.Browser()
    browser.addheaders = user_agent
    page = browser.open(url)
    source_code = page.read()
    print(source_code)
url = "http://whatismyuseragent.dotdoh.com/"
user_agent = [("User-agent", "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) ...")]
test_user_agent(url,user_agnet)
```

网站还会给 Web 浏览器发送 cookie，cookie 中记录了一些能唯一标识用户的信息，网站用它来验证用户之前是否访问/登录过该网站。为了防止这种情况发生，在执行匿名操作之前一定要清除浏览器中的 cookie。有一个库名为 cookielib，其中含有几个不同的能用来处理 cookie 的容器。这里使用的是一个能把各个不同的 cookie 保存到磁盘中的容器。该功能允许用户在收到 cookie 之后，不必把它返回给网站，并能查看其中的内容

```python
import mechanize
import cookielib
def print_cookies(url):
    browser = mechanize.Browser()
    cookie_jar = cookielib.LWPCookieJar()
    browser.set_cookiejar(cookie_jar)
    page = browser.open(url)
    for cookie in cookie_jar:
        print(cookie)
url = "http://www.syngress.com/"
print_cookies(url)
```

### 把代码集成在 Python 类的 AnonBrowser 中

```python
import mechanize, cookielib, random
class AnonBrowser(mechanize.Browser):
    def __init__(self, proxies=[], user_agents=[]):
        mechanize.Browser.__init__(self)
        self.set_handle_robots(False)
        self.proxies = proxies
        self.user_agents = user_agents + ["Mozilla/4.0 FireFox/6.01", "ExactSearch", ...]
        self.cookie_jar = cookielib.LWPCookieJar()
        self.set_cookiejar(self.cookie_jar)
        self.anonymize()
        
   	def clear_cookies(self):
		self.cookie_jar = cookielib.LWPCookieJar()
        self.set_cookiejar(self.cookie_jar)
        
	def change_user_agent(self):
        index = random.randrange(0, len(self.user_agents))
        self.addheaders = [("User-agent", (self.user_agents[index]))]
        
	def change_proxy(self):
        if self.proxies:
            index = random.randrange(0, len(self.proxies))
            self.set_proxies({"http": self.proxies[index]})
            
	def anonymize(self, sleep=False):
        self.clear_cookies()
        self.change_user_agent()
        self.change_proxy()
        if sleep:
            time.sleep(60)
```

anoymize 函数还有一个能让进程休眠 60s 的参数，这会增加使用了匿名化方法前后两次请求在服务器日志中出现的时间间隔

## 用 AnonBrowser 抓取更多的 Web 页面

## 用 Beautiful Soup 解析 href 链接

若要把目标网页上的链接全都分析出来，有两种选择：一种是使用正则表达式对 HTML 代码做搜索和替换操作，另一种是使用一款名为 BeautifulSoup 的强大的第三方库。

```python
from AnonBrowser import *
from BeautifulSoup import BeautifulSoup
import os
import optparser
import re
def print_links(url):
    ab = AnonBrowser()
    ab.anonymize()
    page = ab.open(url)
    html = page.read()
    try:
        print("[+] Printing Links From Regex.")
        link_finder = re.compile('href="(.*?)"')
        links = link_finder.findall(html)
        for link in links:
            print(link)
    except:
        pass
   	try:
        print("[+] Printing Links From BeautifulSoup.")
        soup = BeautifulSoup(html)
        links = soup.findAll(name='a')
        for link in links:
            if link.has_key('href'):
                print(link["href"])
    except:
        pass        
```

### 用 BeautifulSoup 映射图像

BeautifulSoup 允许我们能在任何 HTML 对象中找出所有的 “IMG” 标签，然后 browser 对象就能下载图片，并将其以二进制文件的形式保存到本地硬盘中。

## 研究、调查、发现

### 用 Python 与谷歌 API 交互

谷歌提供了一个应用程序编程接口（API），它让程序员能执行查询操作，获取结果，而不必使用和精通“正常”的谷歌页面。目前谷歌有两个 API，一个简化版的和一个完整版的，使用完整版的 API 需要拥有开发者密钥。简化版的 API 每天仍能进行相当数量的查询，每次搜索能得到约 30 个结果。

```python
import urllib
from AnonBrowser import *
def google(search_term):
    ab = AnonBrowser()
    search_term = urllib.quote_plus(search_term)
    response = ab.open("http://ajax.googleapis.com/ajax/services/searchweb?v=1.0&q={}".format(search_term))
    print(response.read())
google("Boondock Saint")
```

响应的数据是 JSON 格式的

```python
import json
json.load(response)
```

 来编写一个不带任何额外方法的类保存数据，这将使访问各个字段变得更加容易，而不必专门为获取信息而特意去临时解析三层词典。

```python
import json
import urllib
import optparse
from AnonBrowser import *
class GoogleResult:
    def __init__(self, title, text, url):
        self.title = title
        self.text = text
        self.url = url
   	def __repr__(self):
		return self.title
    
def google(search_term):
    ab = AnonBrowser()
    search_term = urllib.quote_plus(search_term)
    response = ab.open("...")
    objects = json.load(response)
    results = list()
    for result in objects["responseData"]["results"]:
        url = result["url"]
        title = result["titleNoFormatting"]
        text = result["content"]
        new_gr = GoogleResult(title, text, url)
        results.append(new_gr)
   	return results
```

### 用 Python 解析 Tweets 个人主页

和谷歌一样，Twitter 也给开发者提供了 API。相关文档位于[网址](https://dev.twitter.com/docs)

```python
import json, urllib
from AnonBrowser import *
class ReconPerson:
    def __init__(self, first_name, last_name, job='', social_media={}):
        self.first_name = first_name
        self.last_name = last_name
        self.job = job
        self.social_media = social_media
        
	def __repr__(self):
        return "{} {} has job {}".format(self.first_name, self.last_name, self.job)
    
    def get_social(self, media_name):
        if self.social_media.has_key(media_name):
            return self.social_media[media_name]
        return None
    
	def query_twitter(self, query):
        query = urllib.quote_plus(query)
        results = list()
        browser = AnonBrowser()
        response = browser.open("http://search.twitter.com/search.json?q={}".format(query))
        json_objects = json.load(response)
        for result in json_objects["results"]:
            new_result = dict()
            new_result["name"] = result["name"]
            new_result["geo"] = result["geo"]
            new_result["tweet"] = result["text"]
            results.append(new_result)
        return results
ap = ReconPerson("Boondock", "Saint")
print(ap.query_twitter("from:username since:2010-01-01 include:retweets"))
```

### 从推文中提取地理位置信息

许多 Twitter 用户遵循一个公式来撰写他们的推文与世界分享。通常情况下，这个公式为：【该推文是直接推给哪些推特用户的】+【推文的正文，其中常会含有简短的 URL】+【hash 标签】。使用恶意的分割法时，这个公式应该写成：【关注该用户的人，他们信任来自该用户的通信的概率会比较大】+【这个人感兴趣的链接或主题，他可能会对该话题中的其他内容感兴趣】+【这个人可能想要进一步了解的大致方向或主题】。

```python
import json
import urllib
import optparse
from AnonBrowser import *
def get_tweets(handle):
    query = urllib.quote_plus("from:{} since:2009-01-01 include:retweets".format(handle))
    tweets = list()
    browser = AnonBrowser()
    browser.anonymize()
    response = browser.open("http://search.twitter.com/search.json?q={}".format(query))
    json_objects = json.load(response)
    for result in json_objects["results"]:
        new_result = {}
        new_result["from_user"] = result["from_user_name"]
        new_result["geo"] = result["geo"]
        new_result["tweet"] = result["text"]
        tweets.append(new_result)
	return tweets

def load_cities(city_file):
    cities = list()
    for line in open(city_file).readlines():
        city = line.split("\r\n").lower()
        cities.append(city)
   	return cities

def twitter_locate(tweets, cities):
    locations = list()
    loc_cnt = 0
    city_cnt = 0
    tweets_text = str()
    for tweet in tweets:
        if tweet["geo"] != None:
            locations.append(tweet["geo"])
            loc_cnt += 1
            tweets_text += tweet["tweet"].lower()
	for city in cities:
        if city in tweets_text:
            locations.append(city)
            city_cnt += 1
	print("[+] Found {} locations via Twitter API and {} locations from text search.".format(loc_cnt, city_cnt))
```

### 用正则表达式解析 Twitter 用户的兴趣爱好

```python
def find_interests(tweets):
    interests = dict()
    interests["links"] = list()
    interests["users"] = list()
    interests["hashtags"] = list()
    for tweet in tweets:
        text = tweet["tweet"]
        links = re.compile('(http.*?)\Z|(http.*?) ').findall(text)
        for link in links:
            if link[0]:
                link = link[0]
           	elif link[1]:
                link = link[1]
			else:
                continue
            try:
                response = urllib2.urlopen(link)
                full_link = response.url
                interests["links"].append(full_link)
            except:
                pass
       	interests["users"] += re.compile("(@\w+)").findall(text)
    	interests["hashtags"] += re.compile("(#\w+)").findall(text)
	interests["users"].sort()
    interests["hashtags"].sort()
    interests["links"].sort()
    return interests
```

由于推文的字数限制，大多数 URL 会使用各个服务商提供的短网址。这些链接里没什么信息量，因为他们可以指向任何地址。为了把短网址转成正常的 URL，可以用 urllib2 打开它们，在脚本打开页面后，urllib 可以获取到完整的 URL

```python
def find_interests(self):
    interests = dict()
    interests["links"] = list()
    interests["users"] = list()
    interests["hashtags"] = list()
    for tweet in self.tweets:
        text = tweet["tweet"]
        links = re.compile("(http.*?)\Z|(http.*?) ").findall(text)
        for link in links:
            if link[0]:
                link = link[0]
            elif link[1]:
                link = link[1]
			else:
                continue
        try:
            response = urllib2.urlopen(link)
            full_link = response.url
			interests["links"].append(full_link)
		except:
            pass
        interests["users"] += re.compile("(@\w+)").findall(text)
        interests["hashtags"] += re.compile("(#\w+)").findall(text)
        interests["users"].sort()
        interests["hashtags"].sort()
        interests["links"].sort()
   	return interests
```

## 匿名电子邮件

相对于获取一个永久性电子邮箱，使用一次性电子邮箱也是另一个很好的选项。Ten Minute Mail 提供的就是这样一种一次性电子邮箱。攻击者可以使用这种很难被追踪的电子邮件账户去创建社交网站账号。

## 批量社工

### 使用 smtplib 给目标对象发邮件

正常发送邮件的过程包括打开邮件客户端，单击相应的选项，然后单击新建，最后单击发送。在电脑屏幕后，邮件客户端程序会连接到服务器，有时还需要登录，并提交详细的信息——发件人、收件人和其他必要的数据。

```python
import smtplib
from email.mime.text import MIMEText
def send_mail(user, pwd, to, subject, text):
    msg = MIMEText(text)
    msg["From"] = user
    msg["To"] = to
    msg["Subject"] = subject
    try:
        smtp_server = smptlib.SMTP("smtp.gmail.com", 587)
        print("[+] Connecting To Mail Server.")
        smtp_server.ehlo()
        print("[+] Starting Encrypted Session.")
        smtp_server.starttls()
        smtp_server.ehlo()
        print("[+] Logging Into Mail Server.")
        smtp_server.login(user, pwd)
        print("[+] Seding Mail.")
        smtp_server.sendmail(user, to, msg.as_string())
        smtp_server.close()
        print("[+] Mail Sent Successfully.")
 	except:
        print("[-] Seding Mail Failed.")
        
user = "username"
pwd = "password"
send_mail(user, pwd, "target@target.target", "Re: Important", "Test Message")
```

不过许多电子邮件服务器是不允许转发邮件的，所以只能将邮件传递到指定的地址。本地电子邮件服务器可以被设为允许转发邮件，或允许转发来自网上的邮件，这是它会把来自任意地址的电子邮件转发的任意地址中——即使邮件地址的格式都不对也没关系。伪造发信地址是关键，使用邮件客户端脚本，再加上一个允许转发邮件的服务器。

### 用 smtplib 进行网络钓鱼

为了降低被识破的概率，只生成一段非常简单的含有恶意代码的文本，把它作为邮件的正文。程序会根据它所拥有的数据，随机生成文本。具体步骤是：选择一个虚拟的发信人电子邮箱地址，指定一个主题，生成正文文本，然后发送电子邮件。

脚本利用目标对象留在 Twitter 中可以公开访问的信息对他进行攻击。根据它会找到关于目标对象的地理位置信息、@过的用户、hash 标签以及链接，脚本就会生成和发送一个带有恶意链接的电子邮件，等待目标对象去点击。

```python
import smtplib
import optparse
from email.mime.text import MIMEText
from twitterCLass import *
from random import choice
def send_main():
    pass
    
def main():
    parser = optparse.OptionParser("usage%prog -u<twitter target> -t<target email> -l <gmail login> -p <gmail password>")
    parser.add_option("-u", dest="handle", type="string", help="specify twitter handle")
    parser.add_option("-t", dest="tgt", type="string", help="specify target email")
    parser.add_option("-l", dest="user", type="string", help="specify gmail login")
    parser.add_option("-p", dest="pwd", type="string", help="speicfy gmail password")
    options, args = parser.parse_args()
    handle = options.handle
    tgt = options.tgt
    user = options.user
    pwd = options.pwd
    if handle == None or tgt == None or user == None or pwd == None:
        print(parser.usage)
        exit(-1)
    print("[+] Fetching tweets from: {}".format(handle))
    spam_tgt = ReconPerson(handle)
    spam_tgt.get_tweets()
    print("[+] Fetching interests from: {}".format(handle))
    interests = spam_tgt.find_interests()
    print("[+] Fetching location information from: {}".format(handle))
    location = spam_tgt.twitter_locate("mlb-cities.txt")
    spam_msg = "Dear {},".format(tgt)
    if location != None:
        rand_loc = choice(location)
        spam_msg += " Its me from {}.".format(rand_loc)
	if interests["users"] != None:
        rand_user = choice(interests["users"])
        spam_msg += " {} said to say hello.".format(rand_user)
    if interests["hashtags"] != None:
        rand_hash = choice(interests["hashtags"])
        spam_msg += " Did you see all the fuss about {}?".format(randHash)
	if interests["links"] != None:
        rand_link = choice(interests["links"])
        spam_msg += " I really liked your link to: {}.".format(rand_link)
	spam_msg += " Check out my link to http://evil.tgt/malware"
    print("[+] Sending Msg: {}".format(spam_msg))
    send_main(user, pwd, tgt, "Re: Important", spam_msg)
```

