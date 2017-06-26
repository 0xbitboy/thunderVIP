# -*- coding: utf-8 -*-

"""
thunderVIP.check
---------------------
Functions for checking accounts.
"""
import requests
import urllib.parse
import utils
import time
import algorithm
import random
from bs4 import BeautifulSoup

LOGIN_URL=" https://login.xunlei.com/sec2login/?csrf_token=";
CSRF_TOKEN="2f1b80cb27c5add8bdec61c707c4c5ae";
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

DEVICE_REPORT_URL="https://login.xunlei.com/risk?cmd=report";
DEVICE_RAW="Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0###zh-CN###24###1440x2560###-480###true###true###true###undefined###undefined######Win32###unspecified###360SoftMgrPlugin::360SoftMgrPlugin::application/360softmgrplugin~dll;360安全卫士 快速登录::360安全卫士 快速登录::application/mozilla-npqihooquicklogin~;APlayer ActiveX hosting plugin::APlayer III ActiveX hosting plugin for Firefox::application/x-thunder-aplayer~ocx;AliSSOLogin plugin::npAliSSOLogin Plugin::application/npalissologin~AliSSOLogin;AliWangWang Plug-In For Firefox and Netscape::npwangwang::application/ww-plugin~dll;AliWangWang Plug-In For Firefox and Netscape::npwangwang::application/ww-plugin~dll;Alipay Security Control 3::Alipay Security Control::application/x-alisecctrl-plugin~*;Alipay Security Payment Client Suit::Alipay Internet Health Control::application/x-aliinethealth-plugin~*;Alipay security control::npaliedit::application/aliedit~ ;Alipay webmod control::npalidcp::application/alidcp~ ;BaiduYunGuanjia Application::YunWebDetect::application/bd-npyunwebdetect-plugin~;China Online Banking Assistant::COBA Plugin DLL::application/coba~*;Foxit Reader Plugin for Mozilla::Foxit Reader Plug-In For Firefox and Netscape::application/pdf~pdf,application/vnd.fdf~fdf,application/vnd.ppdf~ppdf;Google Update::Google Update::application/x-vnd.google.update3webcontrol.3~,application/x-vnd.google.oneclickctrl.9~;Intel® Identity Protection Technology::Intel web components for Intel® Identity Protection Technology::application/x-vnd-intel-webapi-ipt-4.0.5~;Intel® Identity Protection Technology::Intel web components updater - Installs and updates the Intel web components::application/x-vnd-intel-webapi-updater~intel_webapi_updater-2-0;Microsoft Office 2016::The plugin allows you to have a better experience with Microsoft Lync::application/vnd.microsoft.communicator.ocsmeeting~;Microsoft Office 2016::The plugin allows you to have a better experience with Microsoft SharePoint::application/x-sharepoint~,application/x-sharepoint-uc~;NVIDIA 3D VISION::NVIDIA 3D Vision Streaming plugin for Mozilla browsers::application/mozilla-3dv-streaming-plugin~rts;NVIDIA 3D Vision::NVIDIA 3D Vision plugin for Mozilla browsers::image/jps~jps,image/pns~pns,image/mpo~mpo;QQGamePlugin Pro::QQWebGamePlugin Pro::application/npqqwebgame~rts;QQMail Plugin::QQMail plugin for WebKit #1.0.0.22::application/x-tencent-qmail-webkit~,application/x-tencent-qmail~;QQMiniDL Plugin::QQMiniDL Plugin::application/npxf-qqminidl~dll;QQÒôÀÖ²¥·Å¿Ø¼þ::QQÒôÀÖ²¥·Å¿Ø¼þ::application/tecent-qzonemusic-plugin~rts;Tencent FTN plug-in::Tencent FTN plug-in::application/txftn-webkit~;Tencent QQ::Tencent QQ CPHelper plugin for Chrome::application/qscall-plugin~dll;Tencent SSO Platform::QQ QuickLogin Helper::application/nptxsso~;Thunder DapCtrl NPAPI Plugin::Thunder DapCtrl NPAPI Plugin::application/x-thunder-dapctrl~*;XunLei Plugin::Xunlei scriptability Plugin::application/np_xunlei_plugin~*;XunLei User Plugin::Xunlei User scriptability Plugin,version= 2.0.2.3::application/npxluser_plugin~;iTrusChina iTrusPTA,XEnroll,iEnroll,hwPTA,UKeyInstalls Firefox Plugin::iTrusPTA&XEnroll hwPTA,IEnroll,UKeyInstalls for FireFox,version=1.0.0.2::application/pta.itruspta.version.1~*,application/cenroll.cenroll.version.1~,application/itrusenroll.certenroll.version.1~,application/hwpta.itrushwpta~,application/hwwdkey.installwdkey~,application/hwepass2001.installepass2001~;npQQPhotoDrawEx::npQQPhotoDrawEx Module::application/tencent-qqphotodrawex2-plugin~rts;npalicdo plugin::npalicdo::application/npalicdo~dll;xfplay p2p plugin::xfplay p2p plugin::application/xfplay-plugin~dll;歪歪::yy_checker::application/x-checker~;腾讯视频::腾讯视频 version:9.20.2062.0::application/tecent-qqlive-plugin~###";
DEVICE_HEADERS={
    "Origin": "http://i.xunlei.com",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 LBBROWSER",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://i.xunlei.com/login/?r_d=1&use_cdn=0&timestamp=1498380599187&refurl=http%3A%2F%2Fvip.xunlei.com%2F",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.8"
}

def getDeviceId():
    canvasFingerprint = utils.md5Encode(str(time.time()))
    xl_fp_raw = utils.base64Encode(DEVICE_RAW + canvasFingerprint);
    data={
        "xl_fp_raw":xl_fp_raw,
        "xl_fp":utils.md5Encode(xl_fp_raw),
        "xl_fp_sign":algorithm.xl_al(xl_fp_raw)
    }
    print(data)
    response = requests.post(DEVICE_REPORT_URL,data=data,headers=DEVICE_HEADERS)
    return response.cookies['deviceid']

def getCsrfToken(deviceId):
    return utils.md5Encode(str(deviceId)[:32])

def genNewDevice():
    deviceId = getDeviceId();
    LOGIN_HEADERS['Cookie']=("_x_t_=0; deviceid="+deviceId);
    CSRF_TOKEN = getCsrfToken(deviceId);

def login(username,password):
    data={
        "p": password,
        "u": username,
        "verifycode": "",
        "login_enable": "0",
        "business_type": "200",
        "v": "101",
        "cachetime": "1498368983950"
    }
    response=requests.post(LOGIN_URL+CSRF_TOKEN,data=data,headers=LOGIN_HEADERS,verify=False);
    # print(response.content)
    #soup=BeautifulSoup(response.content, "html.parser");
    #print(soup.prettify())

    print(response.cookies)

    blogresult = response.cookies['blogresult'];
    if(blogresult=="10" or blogresult=="22"):
        print("设备号已经触发验证码，更换设备号\n");
        genNewDevice();
        time.sleep(random.randint(2,4))
        return login(username,password);

    success = response.cookies.__contains__("usernick");
    try:
        nickname = response.cookies["usernick"]
        nickname = urllib.parse.unquote(nickname);
    except Exception:
        nickname = "无效"

    return success,nickname

if __name__ == "__main__":
    deviceId=getDeviceId();
    print(deviceId);
    print(getCsrfToken(deviceId))
