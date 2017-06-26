&#160; &#160; &#160; &#160;原本想写个程序去抓一些网站共享的迅雷帐号，然后利用迅雷的web登录接口校验帐号的有效性，后面发现共享的帐号基本都是不能用的，最后还是把web登录接口的协议整理一下，学习一下关于帐号这方面的东西，顺便练练python。

# 迅雷WEB登录协议分析

## 登录的post请求
```
POST https://login.xunlei.com/sec2login/?csrf_token=2f1b80cb27c5add8bdec61c707c4c5ae HTTP/1.1
Host: login.xunlei.com
Connection: keep-alive
Content-Length: 96
Pragma: no-cache
Cache-Control: no-cache
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://i.xunlei.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 LBBROWSER
Content-Type: application/x-www-form-urlencoded
Referer: http://i.xunlei.com/login/?r_d=1&use_cdn=0&timestamp=1498368525595&refurl=http%3A%2F%2Fvip.xunlei.com%2F
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: _x_t_=0; deviceid=wdi10.1a4ab2252ec764cc1896a9be6c9acf1eb6b29f7401450e614905aaea7d3a5a50

p=密码&u=迅雷号&verifycode=&login_enable=0&business_type=200&v=101&cachetime=1498368983950
```
- Cookie中的deviceid是很关键，错误的设备号将无法进行登录
- url中的csrf_token似乎没什么作用，具体的生成算法见后面的分析。
- 安全策略的触发的指纹也是根据deviceid，这个deviceid就是用来区分设备（浏览器）的
- 可以使用固定的deviceid进行请求，但是错误次数到达一定的数量后会触发验证码。

## 返回结果
  登录是否成功不是在返回的response body里面，而是在Cookie中。
  登录成功的结果如下，会有一些中间的key，tonken之类的用于后面的登录校验，一般都是什么单点登录那一套。
```
Set-Cookie:logintype=0; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:jumpkey=xxxxx; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:upgrade=; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:loginkey=xxx10dc; PATH=/; DOMAIN=xunlei.com;EXPIRES=Tue, 25-Jul-17 08:01:38 GMT;
Set-Cookie:state=0; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:isvip=0; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:score=17869; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:accessmode=10001; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:verify_type=; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:usertype=0; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:usernewno=102754732; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:result=200; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:usrname=; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:deviceid=wdi10.1a4ab2252ec764cc1896a9be6c9acf1eb6b29f7401450e614905aaea7d3a5a50; PATH=/; DOMAIN=xunlei.com;EXPIRES=Wed, 23-Jun-27 08:01:38 GMT;
Set-Cookie:userid=xxxxx; PATH=/; DOMAIN=xunlei.com;EXPIRES=Tue, 25-Jul-17 08:01:38 GMT;
Set-Cookie:order=xx; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:blogresult=0; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:sessionid=xxxxx; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:usernick=xxxx; PATH=/; DOMAIN=xunlei.com;
```
登录失败也是在返回的cookie 中 ,blogresult字段不为0的时候表示失败，10表示需要验证码。
```
Set-Cookie:deviceid=wdi10.1a4ab2252ec764cc1896a9be6c9acf1eb6b29f7401450e614905aaea7d3a5a50; PATH=/; DOMAIN=xunlei.com;EXPIRES=Wed, 23-Jun-27 08:01:31 GMT;
Set-Cookie:verify_type=MVA; PATH=/; DOMAIN=xunlei.com;
Set-Cookie:blogresult=10; PATH=/; DOMAIN=xunlei.com;
Via:tw06548
```

# deviceid 与 csrf_token
- 这2个参数使用固定的值确实是可以实现请求，是否有过期机制未校验。
- 这2个参数我觉得就是用来做一些多设备登录的标志还有用来反外挂之类的吧。


1. csrf_token的取值
  csrf_token的取值方法在 http://i.xunlei.com/login/static/aio.js 这个js中的某个模块的方法,从方法可以看出，csrf_token的取值就是deviceid截取32位做一次md5，所以关键还是在deviceid的生成算法上。
  ```
  getCsrfToken: function() {
      return md5(self.getCookie("deviceid").slice(0, 32))
  }
  ```
2. deviceid的取值
  deviceid的值并不是本地生成的，需要将浏览器的设备信息上报的一个接口然后会在cookie写入deviceid值。

  在 的js文件中有这段代码.
  ```
  var fp = (function() {
    return {
      report : function() {
          var fp_raw = new Fingerprint({screen_resolution: true,canvas: true,ie_activex: true}).get();
          var fp = md5(fp_raw);
          var path = "/risk?cmd=report";
          var current = (new Date()).getTime();
          if(store.enabled){
              if(store.get('xl_fp')==fp && Util.getCookie('deviceid') && Util.getCookie('deviceid') == store.get('deviceid') && current-parseInt(store.get('xl_fp_rt'))<7*24*3600*1000 ){
                  return true;//上报指纹情况:1.指纹xl_fp发生变化 2.不存在deviceid 3.deviceid发生变化 4.xl_fp七天过期后
              }
          }else{
              if(Util.getCookie('xl_fp')==fp && Util.getCookie('deviceid')){
                  return true;
              }
          }

          Util.loadScript( '/risk?cmd=algorithm&t='+current, function(){
              var xl_fp_sign =  xl_al(fp_raw);
              Util.requestHelper("POST", path, {xl_fp_raw:fp_raw,xl_fp:fp,xl_fp_sign:xl_fp_sign}, function(){
                  if(store.enabled){
                    store.set('xl_fp',fp);
                    store.set('deviceid',Util.getCookie('deviceid'));
                    store.set('xl_fp_rt',current);
                  }else{
                    Util.setCookie('xl_fp',fp,7*24*3600*1000,'xunlei.com');
                  }
              }, 1000, true);
          }, true);
      }
    };
  })();
  ```

  ```

  POST https://login.xunlei.com/risk?cmd=report HTTP/1.1
  Host: login.xunlei.com
  Connection: keep-alive
  Content-Length: 5899
  Pragma: no-cache
  Cache-Control: no-cache
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
  Origin: http://i.xunlei.com
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 LBBROWSER
  Content-Type: application/x-www-form-urlencoded
  Referer: http://i.xunlei.com/login/?r_d=1&use_cdn=0&timestamp=1498380599187&refurl=http%3A%2F%2Fvip.xunlei.com%2F
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.8
  Cookie: XLA_CI=86c19b61203654648726d13490edeb22; VERIFY_KEY=76C36810C0DFD1A0A61C84307787D321DFAAF6384D1840C9767F9034F0070409; _x_t_=0

  xl_fp_raw=TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV09XNjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS80OS4wLjI2MjMuNzUgU2FmYXJpLzUzNy4zNiBMQkJST1dTRVIjIyN6aC1DTiMjIzI0IyMjMTQ0MHgyNTYwIyMjLTQ4MCMjI3RydWUjIyN0cnVlIyMjdHJ1ZSMjI3VuZGVmaW5lZCMjI2Z1bmN0aW9uIyMjIyMjV2luMzIjIyMjIyNDaHJvbWl1bSBQREYgVmlld2VyOjo6OmFwcGxpY2F0aW9uL3BkZn5wZGY7U2hvY2t3YXZlIEZsYXNoOjpTaG9ja3dhdmUgRmxhc2ggMjAuMCByMDo6YXBwbGljYXRpb24veC1zaG9ja3dhdmUtZmxhc2h%2Bc3dmLGFwcGxpY2F0aW9uL2Z1dHVyZXNwbGFzaH5zcGw7Q2hyb21pdW0gUERGIFZpZXdlcjo6UG9ydGFibGUgRG9jdW1lbnQgRm9ybWF0OjphcHBsaWNhdGlvbi94LWdvb2dsZS1jaHJvbWUtcGRmfnBkZjtNaWNyb3NvZnTCriBXaW5kb3dzIE1lZGlhIFBsYXllciBGaXJlZm94IFBsdWdpbjo6bnAtbXN3bXA6OmFwcGxpY2F0aW9uL3gtbXMtd21wfiosYXBwbGljYXRpb24vYXN4fiosdmlkZW8veC1tcy1hc2YtcGx1Z2lufiosYXBwbGljYXRpb24veC1tcGxheWVyMn4qLHZpZGVvL3gtbXMtYXNmfmFzZixhc3gsKix2aWRlby94LW1zLXdtfndtLCosYXVkaW8veC1tcy13bWF%2Bd21hLCosYXVkaW8veC1tcy13YXh%2Bd2F4LCosdmlkZW8veC1tcy13bXZ%2Bd212LCosdmlkZW8veC1tcy13dnh%2Bd3Z4LCo7TWljcm9zb2Z0IE9mZmljZSAyMDE2OjpUaGUgcGx1Z2luIGFsbG93cyB5b3UgdG8gaGF2ZSBhIGJldHRlciBleHBlcmllbmNlIHdpdGggTWljcm9zb2Z0IFNoYXJlUG9pbnQ6OmFwcGxpY2F0aW9uL3gtc2hhcmVwb2ludH4sYXBwbGljYXRpb24veC1zaGFyZXBvaW50LXVjfjszNjBNTVBsdWdpbjo6MzYwTU1QbHVnaW46OmFwcGxpY2F0aW9uL3gzNjBtbXBsdWdpbn5kbGw7MzYwU29mdE1nclBsdWdpbjo6MzYwU29mdE1nclBsdWdpbjo6YXBwbGljYXRpb24vMzYwc29mdG1ncnBsdWdpbn5kbGw7MzYw5a6J5YWo5Y2r5aOrIOW%2Fq%2BmAn%2BeZu%2BW9lTo6MzYw5a6J5YWo5Y2r5aOrIOW%2Fq%2BmAn%2BeZu%2BW9lTo6YXBwbGljYXRpb24vbW96aWxsYS1ucHFpaG9vcXVpY2tsb2dpbn47VGVuY2VudCBRUTo6VGVuY2VudCBRUSBDUEhlbHBlciBwbHVnaW4gZm9yIENocm9tZTo6YXBwbGljYXRpb24vcXNjYWxsLXBsdWdpbn5kbGw7UVFNaW5pREwgUGx1Z2luOjpRUU1pbmlETCBQbHVnaW46OmFwcGxpY2F0aW9uL25weGYtcXFtaW5pZGx%2BZGxsO1RlbmNlbnQgU1NPIFBsYXRmb3JtOjpRUSBRdWlja0xvZ2luIEhlbHBlcjo6YXBwbGljYXRpb24vbnB0eHNzb347WHVuTGVpIFVzZXIgUGx1Z2luOjpYdW5sZWkgVXNlciBzY3JpcHRhYmlsaXR5IFBsdWdpbix2ZXJzaW9uPSAyLjAuMi4zOjphcHBsaWNhdGlvbi9ucHhsdXNlcl9wbHVnaW5%2BO%2Batquatqjo6eXlfY2hlY2tlcjo6YXBwbGljYXRpb24veC1jaGVja2VyfjtGb3hpdCBSZWFkZXIgUGx1Z2luIGZvciBNb3ppbGxhOjpGb3hpdCBSZWFkZXIgUGx1Zy1JbiBGb3IgRmlyZWZveCBhbmQgTmV0c2NhcGU6OmFwcGxpY2F0aW9uL3BkZn5wZGYsYXBwbGljYXRpb24vdm5kLmZkZn5mZGYsYXBwbGljYXRpb24vdm5kLnBwZGZ%2BcHBkZjtHb29nbGUgVXBkYXRlOjpHb29nbGUgVXBkYXRlOjphcHBsaWNhdGlvbi94LXZuZC5nb29nbGUudXBkYXRlM3dlYmNvbnRyb2wuM34sYXBwbGljYXRpb24veC12bmQuZ29vZ2xlLm9uZWNsaWNrY3RybC45fjtJbnRlbMKuIElkZW50aXR5IFByb3RlY3Rpb24gVGVjaG5vbG9neTo6SW50ZWwgd2ViIGNvbXBvbmVudHMgZm9yIEludGVswq4gSWRlbnRpdHkgUHJvdGVjdGlvbiBUZWNobm9sb2d5OjphcHBsaWNhdGlvbi94LXZuZC1pbnRlbC13ZWJhcGktaXB0LTQuMC41fjtJbnRlbMKuIElkZW50aXR5IFByb3RlY3Rpb24gVGVjaG5vbG9neTo6SW50ZWwgd2ViIGNvbXBvbmVudHMgdXBkYXRlciAtIEluc3RhbGxzIGFuZCB1cGRhdGVzIHRoZSBJbnRlbCB3ZWIgY29tcG9uZW50czo6YXBwbGljYXRpb24veC12bmQtaW50ZWwtd2ViYXBpLXVwZGF0ZXJ%2BaW50ZWxfd2ViYXBpX3VwZGF0ZXItMi0wO01pY3Jvc29mdCBPZmZpY2UgMjAxNjo6VGhlIHBsdWdpbiBhbGxvd3MgeW91IHRvIGhhdmUgYSBiZXR0ZXIgZXhwZXJpZW5jZSB3aXRoIE1pY3Jvc29mdCBMeW5jOjphcHBsaWNhdGlvbi92bmQubWljcm9zb2Z0LmNvbW11bmljYXRvci5vY3NtZWV0aW5nfjtOVklESUEgM0QgVmlzaW9uOjpOVklESUEgM0QgVmlzaW9uIHBsdWdpbiBmb3IgTW96aWxsYSBicm93c2Vyczo6aW1hZ2UvanBzfmpwcyxpbWFnZS9wbnN%2BcG5zLGltYWdlL21wb35tcG87TlZJRElBIDNEIFZJU0lPTjo6TlZJRElBIDNEIFZpc2lvbiBTdHJlYW1pbmcgcGx1Z2luIGZvciBNb3ppbGxhIGJyb3dzZXJzOjphcHBsaWNhdGlvbi9tb3ppbGxhLTNkdi1zdHJlYW1pbmctcGx1Z2lufnJ0cztRUU1haWwgUGx1Z2luOjpRUU1haWwgcGx1Z2luIGZvciBXZWJLaXQgIzEuMC4wLjIyOjphcHBsaWNhdGlvbi94LXRlbmNlbnQtcW1haWwtd2Via2l0fixhcHBsaWNhdGlvbi94LXRlbmNlbnQtcW1haWx%2BO1RlbmNlbnQgRlROIHBsdWctaW46OlRlbmNlbnQgRlROIHBsdWctaW46OmFwcGxpY2F0aW9uL3R4ZnRuLXdlYmtpdH476IW%2B6K6v6KeG6aKROjrohb7orq%2Fop4bpopEgdmVyc2lvbjo5LjIwLjIwNjIuMDo6YXBwbGljYXRpb24vdGVjZW50LXFxbGl2ZS1wbHVnaW5%2BO1FRw5LDtMOAw5bCssKlwrfDhcK%2Fw5jCvMO%2BOjpRUcOSw7TDgMOWwrLCpcK3w4XCv8OYwrzDvjo6YXBwbGljYXRpb24vdGVjZW50LXF6b25lbXVzaWMtcGx1Z2lufnJ0cztucFFRUGhvdG9EcmF3RXg6Om5wUVFQaG90b0RyYXdFeCBNb2R1bGU6OmFwcGxpY2F0aW9uL3RlbmNlbnQtcXFwaG90b2RyYXdleDItcGx1Z2lufnJ0cztYdW5MZWkgUGx1Z2luOjpYdW5sZWkgc2NyaXB0YWJpbGl0eSBQbHVnaW46OmFwcGxpY2F0aW9uL25wX3h1bmxlaV9wbHVnaW5%2BKjtBbGlwYXkgU2VjdXJpdHkgQ29udHJvbCAzOjpBbGlwYXkgU2VjdXJpdHkgQ29udHJvbDo6YXBwbGljYXRpb24veC1hbGlzZWNjdHJsLXBsdWdpbn4qO0FsaXBheSBTZWN1cml0eSBQYXltZW50IENsaWVudCBTdWl0OjpBbGlwYXkgSW50ZXJuZXQgSGVhbHRoIENvbnRyb2w6OmFwcGxpY2F0aW9uL3gtYWxpaW5ldGhlYWx0aC1wbHVnaW5%2BKjtucGFsaWNkbyBwbHVnaW46Om5wYWxpY2RvOjphcHBsaWNhdGlvbi9ucGFsaWNkb35kbGw7QWxpcGF5IHdlYm1vZCBjb250cm9sOjpucGFsaWRjcDo6YXBwbGljYXRpb24vYWxpZGNwfjtBbGlwYXkgc2VjdXJpdHkgY29udHJvbDo6bnBhbGllZGl0OjphcHBsaWNhdGlvbi9hbGllZGl0fjtBUGxheWVyIEFjdGl2ZVggaG9zdGluZyBwbHVnaW46OkFQbGF5ZXIgSUlJIEFjdGl2ZVggaG9zdGluZyBwbHVnaW4gZm9yIEZpcmVmb3g6OmFwcGxpY2F0aW9uL3gtdGh1bmRlci1hcGxheWVyfm9jeDtUaHVuZGVyIERhcEN0cmwgTlBBUEkgUGx1Z2luOjpUaHVuZGVyIERhcEN0cmwgTlBBUEkgUGx1Z2luOjphcHBsaWNhdGlvbi94LXRodW5kZXItZGFwY3RybH4qO1FRR2FtZVBsdWdpbiBQcm86OlFRV2ViR2FtZVBsdWdpbiBQcm86OmFwcGxpY2F0aW9uL25wcXF3ZWJnYW1lfnJ0cztCYWlkdVl1bkd1YW5qaWEgQXBwbGljYXRpb246Oll1bldlYkRldGVjdDo6YXBwbGljYXRpb24vYmQtbnB5dW53ZWJkZXRlY3QtcGx1Z2lufjtpVHJ1c0NoaW5hIGlUcnVzUFRBLFhFbnJvbGwsaUVucm9sbCxod1BUQSxVS2V5SW5zdGFsbHMgRmlyZWZveCBQbHVnaW46OmlUcnVzUFRBJlhFbnJvbGwgaHdQVEEsSUVucm9sbCxVS2V5SW5zdGFsbHMgZm9yIEZpcmVGb3gsdmVyc2lvbj0xLjAuMC4yOjphcHBsaWNhdGlvbi9wdGEuaXRydXNwdGEudmVyc2lvbi4xfiosYXBwbGljYXRpb24vY2Vucm9sbC5jZW5yb2xsLnZlcnNpb24uMX4sYXBwbGljYXRpb24vaXRydXNlbnJvbGwuY2VydGVucm9sbC52ZXJzaW9uLjF%2BLGFwcGxpY2F0aW9uL2h3cHRhLml0cnVzaHdwdGF%2BLGFwcGxpY2F0aW9uL2h3d2RrZXkuaW5zdGFsbHdka2V5fixhcHBsaWNhdGlvbi9od2VwYXNzMjAwMS5pbnN0YWxsZXBhc3MyMDAxfjtBbGlTU09Mb2dpbiBwbHVnaW46Om5wQWxpU1NPTG9naW4gUGx1Z2luOjphcHBsaWNhdGlvbi9ucGFsaXNzb2xvZ2lufkFsaVNTT0xvZ2luO3hmcGxheSBwMnAgcGx1Z2luOjp4ZnBsYXkgcDJwIHBsdWdpbjo6YXBwbGljYXRpb24veGZwbGF5LXBsdWdpbn5kbGw7QWxpV2FuZ1dhbmcgUGx1Zy1JbiBGb3IgRmlyZWZveCBhbmQgTmV0c2NhcGU6Om5wd2FuZ3dhbmc6OmFwcGxpY2F0aW9uL3d3LXBsdWdpbn5kbGwjIyMyMmI0NjkyZjk4ZjBkN2E0OGVlMzc3Mjg5ODFjZDFjNQ%3D%3D&xl_fp=e120375dbfbadc3714f3abba6f162823&xl_fp_sign=0d0aa0ed01dd12dddd74df9a0421f94a&cachetime=1498380599455

  HTTP/1.1 200 OK
  Server: nginx
  Date: Sun, 25 Jun 2017 08:50:01 GMT
  Content-Type: text/plain; charset=utf-8
  Content-Length: 0
  Connection: keep-alive
  Set-Cookie: deviceid=wdi10.267658a6ee93d5625c273414478fd35822997f6b0e17249457263f3fb49fff3c; PATH=/; DOMAIN=xunlei.com;EXPIRES=Wed, 23-Jun-27 08:50:01 GMT;
  Expires: Sun, 25 Jun 2017 09:20:01 GMT
  Cache-Control: max-age=1800
  Via: tw06546
  ```

  参数的说明

  - xl_fp_raw:是浏览器信息的一些字符串做了base64了
  - xl_fp:是xl_fp_raw的md5
  - xl_fp_sign: 执行脚本(https://login.xunlei.com/risk?cmd=algorithm&t=111)中的 xl_al对xl_fp_raw进行签名

--------
  看看 xl_fp_raw的获取 ，使用的是 开源的一个组件 https://github.com/Valve/fingerprintjs
  ```
  Fingerprint.prototype = {
    get: function(){
      var keys = [];
      keys.push(navigator.userAgent);
      keys.push(navigator.language);
      keys.push(screen.colorDepth);
      if (this.screen_resolution) {
        var resolution = this.getScreenResolution();
        if (typeof resolution !== 'undefined'){ // headless browsers, such as phantomjs
          keys.push(resolution.join('x'));
        }
      }
      keys.push(new Date().getTimezoneOffset());
      keys.push(this.hasSessionStorage());
      keys.push(this.hasLocalStorage());
      keys.push(!!window.indexedDB);
      //body might not be defined at this point or removed programmatically
      if(document.body){
        keys.push(typeof(document.body.addBehavior));
      } else {
        keys.push(typeof undefined);
      }
      keys.push(typeof(window.openDatabase));
      keys.push(navigator.cpuClass);
      keys.push(navigator.platform);
      keys.push(navigator.doNotTrack);
      keys.push(this.getPluginsString());
      if(this.canvas && this.isCanvasSupported()){
        keys.push(this.getCanvasFingerprint());
      }
      return Base64.encode(keys.join('###'));
    }
  ```

  原始值大概是这样

  >Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0###zh-CN###24###1440x2560###-480###true###true###true###undefined###undefined######Win32###unspecified###360MMPlugin::360MMPlugin::application/x360mmplugin~dll;360SoftMgrPlugin::360SoftMgrPlugin::application/360softmgrplugin~dll;360安全卫士 快速登录::360安全卫士 快速登录::application/mozilla-npqihooquicklogin~;APlayer ActiveX hosting plugin::APlayer III ActiveX hosting plugin for Firefox::application/x-thunder-aplayer~ocx;AliSSOLogin plugin::npAliSSOLogin Plugin::application/npalissologin~AliSSOLogin;AliWangWang Plug-In For Firefox and Netscape::npwangwang::application/ww-plugin~dll;AliWangWang Plug-In For Firefox and Netscape::npwangwang::application/ww-plugin~dll;Alipay Security Control 3::Alipay Security Control::application/x-alisecctrl-plugin~*;Alipay Security Payment Client Suit::Alipay Internet Health Control::application/x-aliinethealth-plugin~*;Alipay security control::npaliedit::application/aliedit~ ;Alipay webmod control::npalidcp::application/alidcp~ ;BaiduYunGuanjia Application::YunWebDetect::application/bd-npyunwebdetect-plugin~;China Online Banking Assistant::COBA Plugin DLL::application/coba~*;Foxit Reader Plugin for Mozilla::Foxit Reader Plug-In For Firefox and Netscape::application/pdf~pdf,application/vnd.fdf~fdf,application/vnd.ppdf~ppdf;Google Update::Google Update::application/x-vnd.google.update3webcontrol.3~,application/x-vnd.google.oneclickctrl.9~;Intel® Identity Protection Technology::Intel web components for Intel® Identity Protection Technology::application/x-vnd-intel-webapi-ipt-4.0.5~;Intel® Identity Protection Technology::Intel web components updater - Installs and updates the Intel web components::application/x-vnd-intel-webapi-updater~intel_webapi_updater-2-0;Microsoft Office 2016::The plugin allows you to have a better experience with Microsoft Lync::application/vnd.microsoft.communicator.ocsmeeting~;Microsoft Office 2016::The plugin allows you to have a better experience with Microsoft SharePoint::application/x-sharepoint~,application/x-sharepoint-uc~;NVIDIA 3D VISION::NVIDIA 3D Vision Streaming plugin for Mozilla browsers::application/mozilla-3dv-streaming-plugin~rts;NVIDIA 3D Vision::NVIDIA 3D Vision plugin for Mozilla browsers::image/jps~jps,image/pns~pns,image/mpo~mpo;QQGamePlugin Pro::QQWebGamePlugin Pro::application/npqqwebgame~rts;QQMail Plugin::QQMail plugin for WebKit #1.0.0.22::application/x-tencent-qmail-webkit~,application/x-tencent-qmail~;QQMiniDL Plugin::QQMiniDL Plugin::application/npxf-qqminidl~dll;QQÒôÀÖ²¥·Å¿Ø¼þ::QQÒôÀÖ²¥·Å¿Ø¼þ::application/tecent-qzonemusic-plugin~rts;Tencent FTN plug-in::Tencent FTN plug-in::application/txftn-webkit~;Tencent QQ::Tencent QQ CPHelper plugin for Chrome::application/qscall-plugin~dll;Tencent SSO Platform::QQ QuickLogin Helper::application/nptxsso~;Thunder DapCtrl NPAPI Plugin::Thunder DapCtrl NPAPI Plugin::application/x-thunder-dapctrl~*;XunLei Plugin::Xunlei scriptability Plugin::application/np_xunlei_plugin~*;XunLei User Plugin::Xunlei User scriptability Plugin,version= 2.0.2.3::application/npxluser_plugin~;iTrusChina iTrusPTA,XEnroll,iEnroll,hwPTA,UKeyInstalls Firefox Plugin::iTrusPTA&XEnroll hwPTA,IEnroll,UKeyInstalls for FireFox,version=1.0.0.2::application/pta.itruspta.version.1~*,application/cenroll.cenroll.version.1~,application/itrusenroll.certenroll.version.1~,application/hwpta.itrushwpta~,application/hwwdkey.installwdkey~,application/hwepass2001.installepass2001~;npQQPhotoDrawEx::npQQPhotoDrawEx Module::application/tencent-qqphotodrawex2-plugin~rts;npalicdo plugin::npalicdo::application/npalicdo~dll;xfplay p2p plugin::xfplay p2p plugin::application/xfplay-plugin~dll;歪歪::yy_checker::application/x-checker~;腾讯视频::腾讯视频 version:9.20.2062.0::application/tecent-qqlive-plugin~###9c6784b6310a2bf866c280246efe7262

  前面部分信息感觉无紧要，因为这些信息都是很可能重合的，无法达到定位一个个设备的目的，我们看看最后一个字符串9c6784b6310a2bf866c280246efe7262到底是怎么生成的。从Fingerprint.get方法可以看出，这个值是this.getCanvasFingerprint()这个方法返回的。这里的目的应该是获取浏览器的指纹，相同的浏览器是不会变的。看到md5我们就可以直接用随机的md5代替了，不用管这个指纹怎么获取的，就可以达到换设备的目的。

  ```
  getCanvasFingerprint: function () {
    try{
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      var txt = 'thunder network';
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.textBaseline = "alphabetic";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125,1,62,20);
      ctx.fillStyle = "#069";
      ctx.fillText(txt, 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText(txt, 4, 17);
      return md5(canvas.toDataURL());
    }
    catch(e){
      return '';
    }
  }
  ```

  -------
  > 经过测试 测试错误次数太多 或者请求过于频繁 还是会触发 验证码，而且是跟帐号的，换浏览器也一样，可能加代理就可以吧。

  -------
