---
layout: post
title: "某僵尸网络被控端恶意样本分析"
---

**Author: K@GearTeam**

![][0]

# 0x0. 引子

近期, 部署于360云平台( https://cloud.360.cn )的”360天眼威胁感知系统”发现系统告警某合作伙伴刚开通的云主机存在异常流量,联合排查后发现有恶意攻击者利用redis crackit漏洞入侵服务器并种植了名为unama的恶意程序。

360云安全研究员 –“王阳东”对此恶意程序进行较为深入的分析,此样本可能是billgates僵尸网络的一个变种。

<!-- more -->

# 0x1. billgates后门简介

billgates是一个近几年非常活跃的DDoS僵尸网络,此程序组成的僵尸网络遍及世界。网络中bot节点多是一些存在弱口令或软件漏洞的linux主机,攻击者利用ssh爆破、exploit、1day、2day等方式对大量IP进行攻击尝试获得服务器的控制权,并通过部署僵尸木马被控端壮大僵尸网络。僵尸网络根据服务端命令可以实现DDoS攻击、反弹shell等多种操作。

# 0x2. 样本分析

捕获到的样本文件大小为1223123字节,MD5值为EFF1CB4E98BCC8FBCBDCA671D4C4A050。

通过readelf得到的源代码文件名共有44个,从源文件名猜测此程序有较多工作线程。

![][1]

静态分析后发现此样本不同部分间的代码风格差异较大:main函数的代码比较简单粗糙,而主功能类CManager及附属类部分却展现出病毒作者对C++的熟练应用。

## 0x2.a. main函数

### 初始化操作:

程序使用自定义算法从.rodata段解密出配置信息并保存,获取程序文件大小与配置信息中的对应值进行对比实现简单的自校验,然后在父进程路径中查找gdb实现反调试。

![][2]

![][3]

调用自定义解密函数,获取硬编码数据进行拼接,得到如DbSecuritySpt、selinux、getty、/tmp/moni.lod、/tmp/gates.lod等字符串并存储到全局变量。检查当前程序路径确定要执行的功能。 路径和功能的关系如下:

![][4]

若是0,1,2类后门则从硬编码中拼接一串十六进制数字符串(其实是两部分十六进制数,以大写字母O分隔,看似一串),

根据后门类型解密对应部分的十六进制数串,0,1类后门得到的配置是`173.254.230.84:3411:1:1:yz:1`,

2类后门得到的配置是`fk.appledoesnt.com:30000:1:1:yz:1`。用冒号分隔字符串得到6个配置项并保存。

检测文件名是否是“update_temporary”,若是则执行DoUpdate并退出。

执行对应的功能函数。

![][5]

### MainMonitor(守护进程):

进入daemon,产生pid文件/tmp/moni.lod,读取/tmp/notify.file内容并保存,创建线程类CThreadMonGates并启动监视线程,主线程循环sleep挂起。监视线程每分钟判断一下/tmp/gates.lod文件(MainBackdoor功能进程的pid file),

若文件不存在则复制自身到从notify.file中获取到的文件路径并执行新路径下的程序。

![][6]

### MainBeikong(程序安装):

进入daemon模式,调用KillChaos结束/tmp/moni.lod和/tmp/gates.lod指向的旧进程 (病毒作者搞错了strcmp的返回值,所以这里的代码并没有什么卵用),再次结束/tmp/moni.lod,结束/tmp/bill.lock并删除bill.lock。再次结束/tmp/gates.lod并设置自身pid文件。在/etc/init.d、/etc/rc(1-5).d等路径设置S97DbSecuritySpt启动项。

结束/usr/bin/bsd-port/下getty.lock和udevd.lock对应的进程,删除udevd.lock,复制自身到

/usr/bin/bsd-port/getty(对应MainBackdoor)并启动。将当前程序路径写入/tmp/notify.file(守护进程使用),复制当前文件到/usr/bin/.sshd(对应MainMonitor)并启动。执行MainProcess函数。MainProcess函数包含了木马的主要功能。

之所以在安装操作中执行猜测是因为病毒的一处配置错误:

由于之前以字母O分隔的两串hex顺序搞反了,导致2类后门(木马功能主体)得到的是fk.appledoesnt.com这一无效域名,而1类后门(安装程序)却能得到173.254.230.84:3411这个有效IP,所以在没有找到问题原因的情况下在安装函数最后加入主功能函数(MainProcess)也不失为一种临时解决方案。

![][7]

### MainSystool(系统工具替换):

获取当前程序名及参数,调用/usr/bin/dpkgd/下对应的原始系统程序(netstat 、lsof、ps、ss)。从原始系统程序的输出中过滤掉包含木马所在目录、服务端通信端口等信息的行。

![][8]

### MainBackdoor(木马功能主体):

进入daemon,设置pid文件,以 S99selinux为服务名创建启动项。移动系统程序ps、ss、netstat、lsof到/usr/bin/dpkgd/目录,复制自身到/bin、/usr/bin、/usr/sbin下替换ps、ss、netstat、lsof等系统程序,执行主功能函数MainProcess。

![][9]

### MainProcess函数:

主功能函数MainProcess首先挂起2秒,删除升级用的临时文件( ./update_temporary ),根据/etc/resolv.conf和谷歌dns(8.8.8.8、8.8.4.4)初始化CDNSCache类的实例g_dnsCache。

初始化g_cnfgDoing(尝试读取conf.n文件)、g_cmdDoing(尝试读取cmd.n文件)、g_statBase类实例,将g_sProvinceDns中330个IP转为数字形式存入g_provinceDns对象。尝试通过insmod加载当前目录下的xpacket.ko驱动(未发现此文件)。从/usr/lib/libamplify.so中读取IP存入g_AmpResource结构(未发现此文件)。初始化CManager(1076字节),设置信号处理函数,无限循环sleep。


![][10]

## 0x2.b. CManager类(画风突变):

CManager类包含了bot的所有功能,此类拥有很多成员,每个成员实现一定的功能,其主要成员对应列表大致如下:

![][11]

CManager::Initialize函数对成员进行了初始化操作,根据g_cmdDoing检查是否有未处理的命令,若有则立刻执行。

初始化完成员变量后执行`CManager::MainProcess`,根据g_iGatsIsFx的值(此时为1)设置程序工作在被控端模式,获取vectorIPs中的IP (此时只有strConnTgts指向的IP)针对每个IP初始化一个CThreadFXConnection并加入set,完成后无限循环sleep。

CThreadFXConnection线程类最终调用`CManager::FXConnectionProcess`建立与控制服务器的TCP连接,连接建立后调用CManager::ConnectionProcess初始化CInitResponse对象并发送一个通知数据包:

![][12]

其中CInitResponse中包含IP (c0 a8 7a 87) 192.168.122.135,系统版本信息,Cpu及内存等信息。

发送完初始化包后,`CManager::ConnectionProcess`进入收发数据的循环,通过`CManager::RecvCommand`接收数据并封装到CCmdMsg结构,将CCmdMsg加入`CThreadSignaledMessageList<CCmdMsg>`队列。

通过`CManager::SendClientStatus`发送bot状态。

CCmdMsg由`CManager::TastGatesProcess`线程负责从接收队列中取出并分发(CThreadTaskGates线程类启动的线程)。

CCmdMsg大致类型如下:

![][13]

CManager类大致结构如下:

![][14]

![][15]

DDoS攻击最终通过`CManager::DoAtkStartCommand`实现,这个函数读取CCmdMsg中的CTask对象,根据CConfigDoing(conf.n)全局配置设置CThreadAtkCtrl线程对象。`CThreadAtkCtrl::ProcessMain`会根据配置执行普通攻击或内核级攻击。普通攻击通过`CThreadAtkCtrl::DoNormalSubTask`执行,该函数最终调用`CThreadAtkCtrl::StartNormalSubTask`,根据每个任务初始化一个CThreadNormalAtkExcutor线程类。最终线程函数为`CThreadNormalAtkExcutor::ProcessMain`,此函数会根据CSubTask.taskType的值初始化一个CPacketAttack的子类用于执行相应的攻击,type值与攻击类型的对应关系如下:

![][16]

`CThreadNormalAtkExcutor::ProcessMain`根据配置调用Create成员构造特定类型所需的数据。

调用成员函数Do,Do调用MakePacket构造攻击数据包,调用UpdateCurVariant修改数据包的一些属性(如TCP顺序号等),调用SendPacket发送数据包。Do函数被循环调用,直到预定数目的攻击完成。

内核攻击通过调用`CThreadAtkCtrl::DoKernelSubTask`执行(type 0x43),

该函数最终调用`CThreadAtkCtrl::StartKernelSubTask`,初始化CThreadKernelAtkExcutor。

最终执行线程为`CThreadKernelAtkExcutor::ProcessMain`,

此函数fork当前进程,在每个CPU上执行函数`CThreadKernelAtkExcutor::KCfgDev`,此函数发送命令rem_device_all(移除所有设备)、add_device ethN(添加网卡N)、max_before_softirq(改变数据包内核中断阈值)到pktgen设备,N为0、1、2等,指向网卡名称。pktgen设备位于/proc/net/pktgen/kpktgend_X,其中X为当前cpu号。病毒作者在这里犯了一个错误,kpktgend_X中X指关联到当前包产生器的cpu号,但病毒作者在这里用的是网卡号,这个错误导致病毒在生成数据包时只用到了一个cpu,无法充分利用多核多cpu的性能。完成pktgen设备的初始化后,`CThreadKernelAtkExcutor::ProcessMain`调用`CThreadKernelAtkExcutor::KCfgCfg`,此函数通过/proc/net/pktgen/ethN配置包产生器。配置包含攻击目标IP端口、发送攻击数据包数目、包大小随机范围、数据包之间的等待时间、源IP随机范围、源端口随机范围等信息。设置完pktgen的参数后`CThreadKernelAtkExcutor::ProcessMain`向/proc/net/pktgen/pgctrl写入start来启动攻击。

# 0x3. 攻击模拟

修改bot的控制服务器IP到本机并编写简单的控制端脚本,在虚拟机中进行tcp rst攻击实验:

![][17]

在设置攻击目标为192.168.122.1:9876,数据包大小范围为128-500,线程数目为200,攻击次数100并关闭Cpu负载均衡开关后得到的攻击数据包如下:

![][18]

可以看到单个bot在此次攻击中共发送了21268252个攻击数据包,数量惊人。

![][19]

由于Cpu使用率限制选项设为关闭,bot最大化使用系统资源,双核cpu达到192.4%的利用率。

# 0x4. 总结

通过此样本可以发现黑产团队的DDoS攻击实力已经到了”比较娴熟”的地步,而根据样本中不同部分的不同代码风格猜测黑产团队可能存在多人多团队合作的编程方式或“黑吃黑”的代码盗用情况,也许。

IT基础技术不断发展的今天,追逐利益的黑产团队依然在不懈的利用刚暴露出来的漏洞攻击着那些疏忽的操作系统,威胁着用户的数据安全。用户愿意将他们的数据、过程实现、想法放到我们的云平台,是因为他们相信我们能让这些数据的隐私和安全得到有力的保证,360云安全团队持续为您构建一个安全云。

[0]: https://p2.ssl.qhimg.com/t01789d0d78a1f590aa.jpg
[1]: https://p5.ssl.qhimg.com/t01f4330c1f4b758388.png
[2]: https://p2.ssl.qhimg.com/t014fad79b661cbfb32.png
[3]: https://p5.ssl.qhimg.com/t019d76f373a17de05f.png
[4]: https://p0.ssl.qhimg.com/t01a327955601cd17fe.png
[5]: https://p0.ssl.qhimg.com/t01dc529489a70ade49.png
[6]: https://p2.ssl.qhimg.com/t01135f7401e58807aa.png
[7]: https://p1.ssl.qhimg.com/t01257f96bba5ed7f63.png
[8]: https://p5.ssl.qhimg.com/t01da5e1312a6378e8a.png
[9]: https://p1.ssl.qhimg.com/t01361120c640c365cd.png
[10]: https://p0.ssl.qhimg.com/t01cf76d1ce0f91f96e.png
[11]: https://p0.ssl.qhimg.com/t01adcd269f85d676f7.png
[12]: https://p2.ssl.qhimg.com/t0115dc7c3c6828e7ef.png
[13]: https://p4.ssl.qhimg.com/t019eee71a3259be51e.png
[14]: https://p3.ssl.qhimg.com/t019945df4bea3b9931.png
[15]: https://p0.ssl.qhimg.com/t012075ff3339d2d2bc.png
[16]: https://p0.ssl.qhimg.com/t01e7ab690cf05884e2.png
[17]: https://p4.ssl.qhimg.com/t01f457bb8effa07111.png
[18]: https://p3.ssl.qhimg.com/t0177a0a7d0d9982f7a.png
[19]: https://p0.ssl.qhimg.com/t01300c3c1d74c12a69.png
