---
layout: post
title: "云安全系列：360GearTeam再次发现QEMU多个漏洞"
---

![][1]

2016年8月份左右，奇虎360向QEMU官方报告了数个QEMU方面的漏洞。它们允许攻击者攻击虚拟机或宿主机本身，导致拒绝服务或者任意代码执行。

<!-- more -->

**360GearTeam**(原360云安全团队)的安全研究员Terence在”安全客”平台对这部分漏洞给出了相关信息。

# 漏洞1:  CVE-2016-5338

ESP/NCR53C9x controller emulation中,交替进行esp_reg_write和esp_reg_read可以控制s->ti_size的值，导致s->ti_wptr和s->ti_rptr超过s->buf[]数组大小，越界写，可造成qemu虚拟机崩溃或者执行任意代码；

# 漏洞2:  CVE-2016-5337

MegaRAID SAS 8708EM2 Host Bus Adapter emulation中，函数megasas_ctrl_get_info在处理MFI命令读取设备信息时越界读，可造成宿主机信息泄露；

# 漏洞3:  CVE-2016-6351

ESP/NCR53C9x controller emulation中，函数esp_do_dma存在越界写，能够导致qemu虚拟机崩溃或者执行任意代码；

# 漏洞4:  CVE-2016-6490

virtio中，virtqueue_pop函数存在死循环，可造成虚拟机拒绝服务；

# 漏洞5:  CVE-2016-6833

VMWARE VMXNET3 NIC device emulation中，存在UAF漏洞，可导致qemu虚拟机进程崩溃；

# 漏洞6:  CVE-2016-6834

VMWARE VMXNET3 NIC device emulation中，net_tx_pkt_do_sw_fragmentation函数存在死循环，可导致虚拟机拒绝服务；

# 漏洞7:  CVE-2016-6835

VMWARE VMXNET3 NIC device emulation中，vmxnet_tx_pkt_parse_headers函数中未对来自虚拟机中网络数据包的IP头长度做检查，导致越界写，能够导致qemu进程崩溃或者执行任意代码；

# 漏洞8:  CVE-2016-6836

VMWARE VMXNET3 NIC device emulation中，vmxnet3_complete_packet函数在向虚拟机回写数据时未完全初始化，可导致主机信息泄露；

# 漏洞9:  CVE-2016-6888

VMWARE VMXNET3 NIC device emulation中，vmxnet_tx_pkt_init函数在分配内存时，存在一个整数溢出漏洞，可导致虚拟机进程崩溃；

**目前360的安全部门已经提供了解决方案，建议使用相关组件、模块的公有云、私有云平台立即作下相关的补丁升级跟进。**

[1]: https://p0.ssl.qhimg.com/t017bc791afee7cd374.png
