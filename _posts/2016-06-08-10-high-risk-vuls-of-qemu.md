---
layout: post
title: "云计算核心组件QEMU连爆10枚高危漏洞"
---

自5月至今,作为云计算重要基础组件的QEMU已经被连续爆出10枚高危漏洞,从官方网站漏洞描述看,这10枚漏洞分别会造成包括“虚拟机逃逸”、“宿主机运行时信息泄露”、“拒绝服务”等后果。目前QEMU官方已经联合RedHat安全团队处理并披露了这10枚高危漏洞。

这10枚漏洞均由奇虎360信息安全部云安全团队的成员发现并向官方汇报。

<!-- more -->

# 云计算核心模块QEMU

作为支撑云计算的基础模块,QEMU是存在于xen和kvm两款主流云系统平台中,用以实现设备模拟的软件。通过QEMU,用户可以实现在虚拟机中使用键盘,网络通信,磁盘存储等诸多需要硬件设备参与才能实现的功能。

QEMU是一款存在于xen和kvm系统中的用以实现设备模拟的软件,据统计,QEMU在国内云系统市场中的使用率接近90%。QEMU能偶实现在虚拟机中使用键盘,网络通信,磁盘存储等诸多需要硬件设备参与的功能,并且可模拟的硬件设备类型非常丰富,如它提供了10种以上类型设备的网卡设备模拟组件,包括pcnet,rtl8139,ne2000,eepro100,e1000等。

不止针对于企业、政府用户,对于普通的PC用户而言,QEMU也可作为一个模拟器在让你在当前系统中运行新的操作系统,并且还可以是跨平台的其他系统。

漏洞危害:盗取核心信息、中断云服务

![][1]

从官网对于此次漏洞事件的描述中,我们可以知道本次由360安全研究员发现的这10枚高危漏洞会分别造成“虚拟机逃逸”、“宿主机运行时信息泄露”、“拒绝服务”等严重后果。10枚漏洞危害如下:

## CVE-2016-4439 可造成任意代码执行

ESP/NCR53C9x controller emulation 中,函数esp_reg_write()未对s->cmdlen做检查,导致缓冲区溢出,可造成虚拟机任意代码执行;

## CVE-2016-4441 可造成拒绝服务

ESP/NCR53C9x controller emulation 中,函数get_cmd()未对dmalen做检查,导致缓冲区溢出,可造成虚拟机崩溃;

## CVE-2016-4952 可造成拒绝服务

VMWARE PVSCSI paravirtual SCSI bus emulation中,函数pvscsi_ring_init_data()和pvscsi_ring_init_msg()未对ri->reqRingNumPages和ri->cmpRingNumPages检查,导致缓冲区溢出,可造成虚拟机崩溃;

## CVE-2016-4964 可造成拒绝服务

LSI SAS1068 Host Bus Adapter emulation中,函数mptsas_fetch_requests()未对s->state是否可操作进行检查,导致while死循环,造成拒绝服务;

## CVE-2016-5105 可造成信息泄露

MegaRAID SAS 8708EM2 Host Bus Adapter emulation中,函数megasas_dcmd_cfg_read()未对栈上的数据data进行初始化,导致信息泄露;

## CVE-2016-5106 可造成拒绝服务

MegaRAID SAS 8708EM2 Host Bus Adapter emulation中,函数megasas_dcmd_set_properties()未对dma_buf_write的参数进行检查,可导致缓冲区溢出,造成虚拟机崩溃;

## CVE-2016-5107 可造成拒绝服务

MegaRAID SAS 8708EM2 Host Bus Adapter emulation中,函数megasas_lookup_frame()未对s->reply_queue_head的大小进行检查,导致越界读,造成虚拟机崩溃;

## CVE-2016-4453 可造成拒绝服务

VMware-SVGA "chipset" emulation中,函数vmsvga_fifo_run()中,由于虚拟机中的用户可以控制输入数据导致while死循环,造成虚拟机崩溃;

## CVE-2016-4454 可造成信息泄露

VMware-SVGA "chipset" emulation中,函数vmsvga_fifo_read_raw()中,用户可以输入数据控制CMD(stop)的值,导致越解读,能够造成主机运行时信息泄露

## CVE-2016-5105 可造成信息泄露

VMware-SVGA "chipset" emulation中,函数vmsvga_fifo_read_raw()中,用户可以输入数据控制CMD(stop)的值,导致越解读,造成宿主机运行时信息泄露;

如果这些漏洞被黑客或不法分子利用,将会造成云服务用户企业或组织蒙受巨大损失。

首先是核心业务数据泄露,目前众多高新技术企业出于效率与成本考虑都会将核心业务数据储存在云端,一旦出现泄露,该企业将失去在市场中的绝大部分竞争力。其次,黑客可以利用这些漏洞造成云计算拒绝服务,从而导致企业相关业务中断,甚至是整条业务链条的瘫痪。

此外,高明的入侵者可以利用这些漏洞从一台虚拟机向宿主机发起攻击,并最终横向控制云环境中的所有重要数据和设备资源。

# 威胁直指金融、电力等大型企业           

2015年年末,Gartner发布数据报告:“全球大型企业对于云计算的依赖程度逐年增高,部分公司的业务对云计算的依赖性已经超过80%。”这也就意味着未来,云系统安全将越来越直接的影响企业能否正常运作。

据了解,中国地区的用户除了使用公有云以外,还会使用很多自建的私有云、混合云系统,特别是自控系数比较高的金融、电力等大型企业。由于缺乏专人对云安全或虚拟化安全的持续关注与参与,致使此类漏洞长期贮存于企业云系统内部,这对于企业而言,无疑是巨大的安全隐患。

最后,360安全专家建议所有云厂商、运营商留意官方发布的相关漏洞补丁,用打补丁的方式修复这些漏洞,保护自身云系统安全。

[1]: https://p0.ssl.qhimg.com/t01159e7e30d00c6775.png
