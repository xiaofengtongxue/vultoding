#coding = "utf-8"

import requests, re
import json
import time
from bs4 import BeautifulSoup

curl = "http://wechat.doonsec.com/"
durl = ""  #钉钉Token
url = "http://wechat.doonsec.com/search/"
baliyun = "https://help.aliyun.com"
aliurl = "https://help.aliyun.com/noticelist/9213612.html"

def getcsrf():
    header = {
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3939.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
    }
    requests.packages.urllib3.disable_warnings()
    res = requests.get(url = curl, headers = header)
    cookie = res.headers['Set-Cookie']
    soup = BeautifulSoup(res.text, 'html.parser')
    for link in soup.find_all('meta'):
        if link.get('name') == "csrf-token":
            csrf = link.get('content')
            return dostart(csrf, cookie)
        else:
            pass

def dostart(csrf, cookie):
    timetoday = time.strftime("%Y-%m-%d", time.localtime())
    heder = {
        "Proxy-Connection": "keep-alive",
        "Content-Length": "33",
        "Accept": "*/*",
        "Origin": "http://wechat.doonsec.com",
        "X-CSRFToken": csrf,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3939.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cookie": cookie
    }
    data = {"page": 1, "keyword": "漏洞预警 | 漏洞通告 | POC公开"}
    requests.packages.urllib3.disable_warnings()
    res = requests.post(url = url, headers = heder, data = data)
    if res.status_code == 200:
        resall = json.loads(res.text)
        tmplist = ""
        for i in resall['data']:
            ptime = i['publish_time']
            if ptime.split(" ")[0] == timetoday:
                ptitle = i['title']
                purl = i['url']
                if "&chksm" in purl:
                    purl = purl.split("&chksm")[0]
                pname = i['account_name']
                tmplist = tmplist + f"\n\n漏洞名称：{ptitle}\n\n通告链接：[点击跳转]({purl})\n\n收录时间：{ptime}\n\n来源信息：{pname}\n\n----"
            else:
                pass
        tmplist = tmplist.strip("\n\n")
        return tmplist

def getaliyun():
    timetoday = time.strftime("%Y-%m-%d", time.localtime())
    headers = {
        'Content-Type': 'application/json;charset=utf-8',
        'user_agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    }
    requests.packages.urllib3.disable_warnings()
    req = requests.get(url = aliurl, headers = headers)
    re_link = re.findall(r'<a href="(.*?)" >【漏洞通告】', req.text)
    re_time = re.findall(r'<span class="y-right">(.*?)<span class="time">', req.text)
    re_second = re.findall(r'<span class="time">(.*?)</span></span>', req.text)  #原始时间
    url_list = []
    for i in range(5):
        if timetoday == re_time[i]:
            vlu_link = baliyun + re_link[i]
            ttime = f'{re_time[i]} {re_second[i]}'
            url_list.append(vlu_link)
    return getvuls(url_list)

def getvuls(urls):
    headers = {
        'Content-Type': 'application/json;charset=utf-8',
        'user_agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    }
    ptime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    tmplist = ""
    for url in urls:
        requests.packages.urllib3.disable_warnings()
        req = requests.get(url=url, headers = headers)
        res = BeautifulSoup(req.text, "html.parser")
        vlu_name = res.h3.get_text()
        tmplist = tmplist + f"\n\n漏洞名称：{vlu_name}\n\n通告链接：[点击跳转]({url})\n\n收录时间：{ptime}\n\n来源信息：阿里云安全公告\n\n----"
    tmplist = tmplist.strip("\n\n")
    return tmplist

def gethuawei():
    import time
    timetoday = time.strftime("%Y-%m-%d", time.localtime())
    hwapi = "https://portal.huaweicloud.com/rest/cbc/portalapppublishservice/v1/content/list_by_graph?graphCode=es_notice_list&page=1&pageSize=8&filter=noticeType:securecenter"
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'user_agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
        'Origin': 'https://www.huaweicloud.com',
        'Referer': 'https://www.huaweicloud.com/notice.securecenter.html'
    }
    requests.packages.urllib3.disable_warnings()
    req = requests.get(url = hwapi, headers = headers)
    res = json.loads(req.text)
    tmplist = ''
    if res['message'] == "success":
        pocdata = res['data']
        for i in pocdata:
            if i['contentTime'].split(" ")[0] == timetoday:
                time = i['contentTime']
                name = i['contentTitle']
                url = i['url']
                tmplist = tmplist + f"\n\n漏洞名称：{name}\n\n通告链接：[点击跳转]({url})\n\n收录时间：{time}\n\n来源信息：华为云安全公告\n\n----"
    tmplist = tmplist.strip("\n\n")
    return tmplist

def gettenxun():
    import time
    timetoday = time.strftime("%Y-%m-%d", time.localtime())
    turl = "https://cloud.tencent.com/announce/ajax"
    burl = "https://cloud.tencent.com/announce/detail/"
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'user_agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
        'Origin': 'https://cloud.tencent.com',
        'Referer': 'https://cloud.tencent.com/announce?categorys=21&page=1'
    }
    i_data = {"action": "getAnnounceList", "data": {"rp": 10,"page": "1", "categorys": ["21"], "labs": [], "keyword": ""}}
    requests.packages.urllib3.disable_warnings()
    req = requests.post(url = turl, data = json.dumps(i_data), headers = headers)
    res = json.loads(req.text)
    tmplist = ''
    if res['code'] == 0:
        pocdata = res['data']['rows']
        for i in pocdata:
            if i['addTime'].split(" ")[0] == timetoday:
                url = f"{burl}{i['announceId']}"
                name = i['title']
                time = i['addTime']
                tmplist = tmplist + f"\n\n漏洞名称：{name}\n\n通告链接：[点击跳转]({url})\n\n收录时间：{time}\n\n来源信息：腾讯云安全公告\n\n----"
    tmplist = tmplist.strip("\n\n")
    return tmplist


def toding(msg):
    dtime = time.strftime("%Y-%m-%d", time.localtime())
    msg = msg.strip("\n\n")
    if msg == "":
        msg = f"今天暂未发现安全漏洞通告"
    hmsg = f"最新漏洞情报推送\n\n推送时间：{dtime}\n\n-----\n\n"
    tmsg = hmsg + msg
    program = {
        "msgtype": "markdown",
        "markdown": {
            "title": "漏洞通知",
            "text": tmsg
        },
        "at": {
            "atMobiles": [],
            "isAtAll": False
        }
    }
    postdata = json.dumps(program)
    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    requests.packages.urllib3.disable_warnings()
    res = requests.post(durl, postdata, headers = headers)
    return res.status_code

def tomsgd():
    vulsh = getcsrf()
    vulsm = getaliyun()
    vultx = gettenxun()
    vulhw = gethuawei()
    msg = f'{vulsh}\n\n{vulsm}\n\n{vultx}\n\n{vulhw}'
    toding(msg.strip("\n\n"))

if __name__ == '__main__':
    tomsgd()

