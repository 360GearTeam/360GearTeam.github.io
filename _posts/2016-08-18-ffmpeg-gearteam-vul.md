---
layout: post
title: "FFMpeg 3.1.2 发布 修复来自360GearTeam的一个高危漏洞"
---

360GearTeam(原360云安全团队)安全研究员 连一汉 近期研究FFMpeg的安全性时，发现FFMpeg在解码swf文件时存在一个缓冲区溢出漏洞，编号CVE-2016-6671。该漏洞在一定条件下能导致任意代码执行，建议使用FFMpeg解码SWF文件的处理平台尽快进行补丁修复处理，目前FFMpeg 3.1.2已经解决该漏洞。

![][1]

<!-- more -->

FFmpeg是一套可以用来记录、转换数字音频、视频，并能将其转化为流的开源计算机程序，包括了目前领先的音/视频编码库 libavcodec， 这个项目是由Fabrice Bellard发起的（也是QEMU项目的发起者）。

360GearTeam发现的CVE-2016-6671漏洞主要存在于在对swf文件进行raw解码时(源码阅读上的理解)，计算解码后的数据大小存在错误，导致写入数据的大小超过申请内存空间的大小，造成缓冲区内存溢出。

![][2]

[1]: https://p4.ssl.qhimg.com/t01349ea32f69b00cd7.png
[2]: https://p2.ssl.qhimg.com/t012bd3b2afbe786f07.png