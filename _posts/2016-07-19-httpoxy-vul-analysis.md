---
layout: post
title: "深夜出炉：httpoxy远程代理感染漏洞浅析（更新poc）"
---

**Author: cyg07@GearTeam**

![][0]

# 0x01 前言

httpoxy是一个刚暴露出来的漏洞，该漏洞主要存在于apache等组件中会对HTTP头部的Proxy字段名变换为“HTTP_PROXY”，Value值不变，进而会传递给对应的CGI来执行。如果CGI或者脚本中使用对外请求的组件依赖的是“HTTP_PROXY”这个环境变量，那就可能被污染。

比较严重的情况是在CGI内部请求的连接是一个涉及到内部隐私的链接，那就有可能比较严峻。

<!-- more -->

# 0x02 实践测试

原理上的东西基本“前言“也囊括了，这里给个简单的测试例子吧。

1. 在 123.59.120.9 使用apache搭建一个cgi-bin服务
2. 在里头创建一个叫“360sec.sh“，内容如下

    ![][1]

3. 模拟做一个请求，注意其中的 Proxy 字段(123.59.119.25:3000 是我做的一个代理)

    ![][2]

4. 请求完了，你可以在 123.59.119.25 上看到 123.59.120.9 的请求

    ![][3]

注意：其实wget和curl使用的都是小写的“http_proxy“，不会被这个影响到，例子为了方便我就修改了下，本质上是一样的。

# 0x03 关于影响

高兴和不高兴的是，

1. 很多内部API还是使用可信的ssl来通信，这样实际是不受影响的
2. 虽然https://httpoxy.org/ 举了部分的例子，但看上去并没有影响得那么多
3. 最开心的是wget/curl不受影响，有其它异议的可以反馈过来
4. 不过以邪恶的心态看待，估计接下来就要开始爆发各种攻击姿势了，不确定能涨出什么样的姿势

# 0x04 关于修复

冷静点，看待这个洞，不过这是个郁闷的修复工作。

给个已经有内幕的链接。

<https://access.redhat.com/security/vulnerabilities/httpoxy>

# 0x05 更新poc

<https://github.com/httpoxy/php-fpm-httpoxy-poc>

[0]: https://p2.ssl.qhimg.com/t014f8b8499122fbbaf.png
[1]: https://p1.ssl.qhimg.com/t01013f3703902e55b1.png
[2]: https://p0.ssl.qhimg.com/t01035e84cbf5a25eb4.png
[3]: https://p3.ssl.qhimg.com/t01e3298a3302d2470f.png
