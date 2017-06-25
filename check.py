# -*- coding: utf-8 -*-

"""
thunderVIP.check
---------------------
Functions for checking accounts.
"""
import requests
from bs4 import BeautifulSoup

LOGIN_URL=" https://login.xunlei.com/sec2login/?csrf_token=1f1b80cb27c5add8bdec61c707c4c5ae";
LOGIN_HEADERS={
    "Origin": "http://i.xunlei.com",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 LBBROWSER",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://i.xunlei.com/login/?r_d=1&use_cdn=0&timestamp=1498368525595&refurl=http%3A%2F%2Fvip.xunlei.com%2F",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.8",
    "Cookie": "_x_t_=0; deviceid=wdi10.1a4ab2252ec764cc1896a9be6c9acf1eb6b29f7401450e614905aaea7d3a5a50"
}

def check(username,password):

    data={
        "p": password,
        "u": username,
        "verifycode": "",
        "login_enable": "0",
        "business_type": "200",
        "v": "101",
        "cachetime": "1498368983950"
    }
    response=requests.post(LOGIN_URL,data=data,headers=LOGIN_HEADERS,verify=False);
    # print(response.content)
    #soup=BeautifulSoup(response.content, "html.parser");
    #print(soup.prettify())

    print(response.cookies)

    pass

if __name__ == "__main__":
    check("username","password");
