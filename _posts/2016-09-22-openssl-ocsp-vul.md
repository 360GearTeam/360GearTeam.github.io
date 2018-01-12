---
layout: post
title: "OpenSSL OCSP状态请求扩展存在严重漏洞"
---

![][1]

# 概述

OpenSSL OCSP 状态请求扩展存在严重漏洞，该漏洞令恶意客户端能耗尽服务器内存。利用该漏洞，能使默认配置的服务器在每次协议重商时分配一段 OCSP ids 内存， 不断重复协商可令服务器内存无限消耗，即使服务器并未配置 OCSP。理论上，一个 OCSP id 最多 65,535 字节，攻击者可以不断重商令服务器每次内存消耗近 64K。但从实现来说，在 OpenSSL 1.0.2 版本中对 ClientHello 长度做了 16,384 字节的限制，因此每次重商只能令服务器内存消耗约 16K。但在最新的 1.1.0 版本中，对 ClientHello 长度的限制增加到 131,396 字节，那么对使用 1.1.0 版本的服务器，每次重商会令内存消耗近 64K。此漏洞由来自360Gear Team的 石磊 (360信息安全部)在阅读 OpenSSL 源码时发现。发现漏洞后报给了 OpenSSL 官方。

<!-- more -->

# 对策

升级到最新版本可避免被攻击。 不需要注销私钥或证书，攻击者不能窃取到私钥。 

补丁地址：<https://www.openssl.org/source/>

# 问题

攻击者可通过发送大量 OCSP 状态请求扩展导致服务器拒绝服务。

# 如何利用

攻击者使用 TLS 扩展 "TLSEXT_TYPE_status_request"，填充 OCSP ids 并不断请求重商。

# 受影响版本

## 影响版本：

* OpenSSL 0.9.8h through 0.9.8v
* OpenSSL 1.0.1 through 1.0.1t
* OpenSSL 1.0.2 through 1.0.1h
* OpenSSL 1.1.0

## 不受影响版本：

* OpenSSL 1.0.1u
* OpenSSL 1.0.2i
* OpenSSL 1.1.0a

# 漏洞危害

攻击者可通过不断重商，发送大量 OCSP 状态请求扩展，导致服务器内存无限增长，最终导致服务器拒绝服务。默认OpenSSL配置的服务器会受影响，即使其并不支持 OCSP，除非在编译时使用了“no-ocsp”编译选项。

# 漏洞利用的影响范围

我们只测试了小部分使用OpenSSL OCSP功能的组件，包括OpenSSL Server、Nginx、和Apache。其中默认配置的 OpenSSL server 是受影响的(包括:OpenSSL 0.9.8h through 0.9.8v、OpenSSL 1.0.1 through 1.0.1t、OpenSSL 1.0.2 through 1.0.1h、OpenSSL 1.1.0)。 Nginx 0.8.23 以前的版本会受此影响，Apache 2.0以前及 SSLInsecureRenegotiation 配置项为 on 是都会受此影响。所有版本 (SSL3.0, TLS1.0, TLS1.1, TLS1.2) 都受影响。 所有加密算法都受影响.

# 参考

OpenSSL

CVE-2016-6304

可以在CC0协议下使用此图标。[下载SVG格式图标](http://security.360.cn/cve/CVE-2016-6304/logo.svg)

# 致谢

感谢 CCS Injection 团队的模板。

感谢 360信息安全部、NetOPS、Hulk、Qiyun 团队的支持。

[1]: https://p0.ssl.qhimg.com/t01520a7bf64e0a6a8b.png