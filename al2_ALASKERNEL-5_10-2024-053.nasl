#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2024-053.
##

include('compat.inc');

if (description)
{
  script_id(192738);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2023-52429",
    "CVE-2023-52435",
    "CVE-2023-52486",
    "CVE-2023-52489",
    "CVE-2023-52492",
    "CVE-2023-52498",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52615",
    "CVE-2023-52616",
    "CVE-2023-52619",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52642",
    "CVE-2023-52672",
    "CVE-2023-6270",
    "CVE-2024-0340",
    "CVE-2024-1151",
    "CVE-2024-2193",
    "CVE-2024-23850",
    "CVE-2024-23851",
    "CVE-2024-26581",
    "CVE-2024-26602",
    "CVE-2024-26614",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26635",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26644",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26685",
    "CVE-2024-26689",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26698",
    "CVE-2024-26704",
    "CVE-2024-26707",
    "CVE-2024-26720",
    "CVE-2024-26727",
    "CVE-2024-26808",
    "CVE-2024-26910",
    "CVE-2024-26917",
    "CVE-2024-26920",
    "CVE-2024-26972",
    "CVE-2024-35835",
    "CVE-2024-50017"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2024-053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.210-201.852. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2024-053 advisory.

    dm_table_create in drivers/md/dm-table.c in the Linux kernel through 6.7.4 can attempt to (in
    alloc_targets) allocate more than INT_MAX bytes, and crash, because of a missing check for struct
    dm_ioctl.target_count. (CVE-2023-52429)

    In the Linux kernel, the following vulnerability has been resolved:

    net: prevent mss overflow in skb_segment()

    Once again syzbot is able to crash the kernel in skb_segment() [1]

    GSO_BY_FRAGS is a forbidden value, but unfortunately the followingcomputation in skb_segment() can reach
    it quite easily :

    mss = mss * partial_segs;

    65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead toa bad final result.

    Make sure to limit segmentation so that the new mss value is smallerthan GSO_BY_FRAGS.

    [1]

    general protection fault, probably for non-canonical address 0xdffffc000000000e: 0000 [#1] PREEMPT SMP
    KASANKASAN: null-ptr-deref in range [0x0000000000000070-0x0000000000000077]CPU: 1 PID: 5079 Comm: syz-
    executor993 Not tainted 6.7.0-rc4-syzkaller-00141-g1ae4cd3cbdd0 #0Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 11/10/2023RIP: 0010:skb_segment+0x181d/0x3f30
    net/core/skbuff.c:4551Code: 83 e3 02 e9 fb ed ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48
    b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <0f> b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48 8b 84
    24 f8 00RSP: 0018:ffffc900043473d0 EFLAGS: 00010202RAX: dffffc0000000000 RBX: 0000000000010046 RCX:
    ffffffff886b1597RDX: 000000000000000e RSI: ffffffff886b2520 RDI: 0000000000000070RBP: ffffc90004347578
    R08: 0000000000000005 R09: 000000000000ffffR10: 000000000000ffff R11: 0000000000000002 R12:
    ffff888063202ac0R13: 0000000000010000 R14: 000000000000ffff R15: 0000000000000046FS:
    0000555556e7e380(0000) GS:ffff8880b9900000(0000) knlGS:0000000000000000CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033CR2: 0000000020010000 CR3: 0000000027ee2000 CR4: 00000000003506f0DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400Call Trace:<TASK>udp6_ufo_fragment+0xa0e/0xd00
    net/ipv6/udp_offload.c:109ipv6_gso_segment+0x534/0x17e0
    net/ipv6/ip6_offload.c:120skb_mac_gso_segment+0x290/0x610 net/core/gso.c:53__skb_gso_segment+0x339/0x710
    net/core/gso.c:124skb_gso_segment include/net/gso.h:83 [inline]validate_xmit_skb+0x36c/0xeb0
    net/core/dev.c:3626__dev_queue_xmit+0x6f3/0x3d60 net/core/dev.c:4338dev_queue_xmit
    include/linux/netdevice.h:3134 [inline]packet_xmit+0x257/0x380 net/packet/af_packet.c:276packet_snd
    net/packet/af_packet.c:3087 [inline]packet_sendmsg+0x24c6/0x5220
    net/packet/af_packet.c:3119sock_sendmsg_nosec net/socket.c:730 [inline]__sock_sendmsg+0xd5/0x180
    net/socket.c:745__sys_sendto+0x255/0x340 net/socket.c:2190__do_sys_sendto net/socket.c:2202
    [inline]__se_sys_sendto net/socket.c:2198 [inline]__x64_sys_sendto+0xe0/0x1b0
    net/socket.c:2198do_syscall_x64 arch/x86/entry/common.c:52 [inline]do_syscall_64+0x40/0x110
    arch/x86/entry/common.c:83entry_SYSCALL_64_after_hwframe+0x63/0x6bRIP: 0033:0x7f8692032aa9Code: 28 00 00
    00 75 05 48 83 c4 28 c3 e8 d1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c
    24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48RSP: 002b:00007fff8d685418
    EFLAGS: 00000246 ORIG_RAX: 000000000000002cRAX: ffffffffffffffda RBX: 0000000000000003 RCX:
    00007f8692032aa9RDX: 0000000000010048 RSI: 00000000200000c0 RDI: 0000000000000003RBP: 00000000000f4240
    R08: 0000000020000540 R09: 0000000000000014R10: 0000000000000000 R11: 0000000000000246 R12:
    00007fff8d685480R13: 0000000000000001 R14: 00007fff8d685480 R15: 0000000000000003</TASK>Modules linked
    in:---[ end trace 0000000000000000 ]---RIP: 0010:skb_segment+0x181d/0x3f30 net/core/skbuff.c:4551Code: 83
    e3 02 e9 fb ed ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48 b8 00 00 00 00 00 fc ff df 48
    89 fa 48 c1 ea 03 <0f> b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48 8b 84 24 f8 00RSP:
    0018:ffffc900043473d0 EFLAGS: 00010202RAX: dffffc0000000000 RBX: 0000000000010046 RCX:
    ffffffff886b1597RDX: 000000000000000e RSI: ffffffff886b2520 RDI: 0000000000000070RBP: ffffc90004347578 R0
    ---truncated--- (CVE-2023-52435)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Don't unref the same fb many times by mistake due to deadlock handling (CVE-2023-52486)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/sparsemem: fix race in accessing memory_section->usage (CVE-2023-52489)

    In the Linux kernel, the following vulnerability has been resolved:

    dmaengine: fix NULL pointer in channel unregistration function (CVE-2023-52492)

    In the Linux kernel, the following vulnerability has been resolved:

    PM: sleep: Fix possible deadlocks in core system-wide PM code (CVE-2023-52498)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: fix deadlock or deadcode of misusing dget() (CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved:

    IB/ipoib: Fix mcast list locking (CVE-2023-52587)

    In the Linux kernel, the following vulnerability has been resolved:

    hwrng: core - Fix page fault dead lock on mmap-ed hwrng (CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: lib/mpi - Fix unexpected pointer access in mpi_ec_init (CVE-2023-52616)

    In the Linux kernel, the following vulnerability has been resolved:

    pstore/ram: Fix crash when setting number of cpus to an odd number (CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid online resizing failures due to oversized flex bg (CVE-2023-52622)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: Fix a suspicious RCU usage warning (CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved:

    PM / devfreq: Synchronize devfreq_monitor_[start/stop] (CVE-2023-52635)

    In the Linux kernel, the following vulnerability has been resolved:

    can: j1939: Fix UAF in j1939_sk_match_filter during setsockopt(SO_J1939_FILTER) (CVE-2023-52637)

    In the Linux kernel, the following vulnerability has been resolved:

    media: rc: bpf attach/detach requires write permission (CVE-2023-52642)

    In the Linux kernel, the following vulnerability has been resolved:

    pipe: wakeup wr_wait after setting max_usage (CVE-2023-52672)

    A flaw was found in the ATA over Ethernet (AoE) driver in the Linux kernel. The aoecmd_cfg_pkts() function
    improperly updates the refcnt on `struct net_device`, and a use-after-free can be triggered by racing
    between the free on the struct and the access through the `skbtxq` global queue. This could lead to a
    denial of service condition or potential code execution. (CVE-2023-6270)

    A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file. (CVE-2024-0340)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues. (CVE-2024-1151)

    A Speculative Race Condition (SRC) vulnerability that impacts modern CPU architectures supporting
    speculative execution (related to Spectre V1) has been disclosed. An unauthenticated attacker can exploit
    this vulnerability to disclose arbitrary data from the CPU using race conditions to access the speculative
    executable code paths. (CVE-2024-2193)

    In btrfs_get_root_ref in fs/btrfs/disk-io.c in the Linux kernel through 6.7.1, there can be an assertion
    failure and crash because a subvolume can be read out too soon after its root item is inserted upon
    subvolume creation. (CVE-2024-23850)

    copy_params in drivers/md/dm-ioctl.c in the Linux kernel through 6.7.1 can attempt to allocate more than
    INT_MAX bytes, and crash, because of a missing param_kernel->data_size check. This is related to
    ctl_ioctl. (CVE-2024-23851)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_set_rbtree: skip end interval element from gc

    rbtree lazy gc on insert might collect an end interval element that hasbeen just added in this
    transactions, skip end interval elements thatare not yet active. (CVE-2024-26581)

    In the Linux kernel, the following vulnerability has been resolved:

    sched/membarrier: reduce the ability to hammer on sys_membarrier

    On some systems, sys_membarrier can be very expensive, causing overallslowdowns for everything.  So put a
    lock on the path in order toserialize the accesses to prevent the ability for this to be called attoo high
    of a frequency and saturate the machine. (CVE-2024-26602)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: make sure init the accept_queue's spinlocks once (CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: call sock_orphan() at release time (CVE-2024-26625)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: core: Move scsi_host_busy() out of host lock for waking up EH handler (CVE-2024-26627)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: Drop support for ETH_P_TR_802_2. (CVE-2024-26635)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: add sanity checks to rx zerocopy (CVE-2024-26640)

    In the Linux kernel, the following vulnerability has been resolved:

    ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: don't abort filesystem when attempting to snapshot deleted subvolume (CVE-2024-26644)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (CVE-2024-26663)

    In the Linux kernel, the following vulnerability has been resolved:

    tunnels: fix out of bounds access when building IPv6 PMTU error (CVE-2024-26665)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-mq: fix IO hang from sbitmap wakeup race (CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_ct: sanitize layer 3 and 4 protocol number in custom expectations (CVE-2024-26673)

    In the Linux kernel, the following vulnerability has been resolved:

    ppp_async: limit MRU to 64K (CVE-2024-26675)

    In the Linux kernel, the following vulnerability has been resolved:

    inet: read sk->sk_family once in inet_recv_error() (CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix potential bug in end_buffer_async_write (CVE-2024-26685)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: prevent use-after-free in encode_cap_msg() (CVE-2024-26689)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix hang in nilfs_lookup_dirty_data_buffers() (CVE-2024-26696)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix data corruption in dsync block recovery for small block sizes (CVE-2024-26697)

    In the Linux kernel, the following vulnerability has been resolved:

    hv_netvsc: Fix race condition between netvsc_probe and netvsc_remove (CVE-2024-26698)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix double-free of blocks due to wrong extents moved_len (CVE-2024-26704)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hsr: remove WARN_ONCE() in send_hsr_supervision_frame() (CVE-2024-26707)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again (CVE-2024-26720)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: do not ASSERT() if the newly created subvolume already got read (CVE-2024-26727)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain (CVE-2024-26808)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: ipset: fix performance regression in swap operation (CVE-2024-26910)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: Revert scsi: fcoe: Fix potential deadlock on &fip->ctlr_lock (CVE-2024-26917)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing/trigger: Fix to return error if failed to alloc snapshot (CVE-2024-26920)

    In the Linux kernel, the following vulnerability has been resolved:

    ubifs: ubifs_symlink: Fix memleak of inode->i_link in error path (CVE-2024-26972)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: fix a double-free in arfs_create_groups (CVE-2024-35835)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/mm/ident_map: Use gbpages only where full GB page should be mapped. (CVE-2024-50017)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2024-053.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52429.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52435.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52486.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52489.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52492.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52498.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52583.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52587.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52615.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52637.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52642.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6270.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0340.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-1151.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-2193.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23850.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26581.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26602.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26614.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26640.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26641.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26644.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26665.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26671.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26673.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26679.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26689.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26697.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26698.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26704.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26707.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26727.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26808.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26910.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26917.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26920.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26972.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50017.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26704");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.210-201.852");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-6270", "CVE-2023-52429", "CVE-2023-52435", "CVE-2023-52486", "CVE-2023-52489", "CVE-2023-52492", "CVE-2023-52498", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52615", "CVE-2023-52616", "CVE-2023-52619", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52635", "CVE-2023-52637", "CVE-2023-52642", "CVE-2023-52672", "CVE-2024-0340", "CVE-2024-1151", "CVE-2024-2193", "CVE-2024-23850", "CVE-2024-23851", "CVE-2024-26581", "CVE-2024-26602", "CVE-2024-26614", "CVE-2024-26625", "CVE-2024-26627", "CVE-2024-26635", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26644", "CVE-2024-26663", "CVE-2024-26665", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26685", "CVE-2024-26689", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26698", "CVE-2024-26704", "CVE-2024-26707", "CVE-2024-26720", "CVE-2024-26727", "CVE-2024-26808", "CVE-2024-26910", "CVE-2024-26917", "CVE-2024-26920", "CVE-2024-26972", "CVE-2024-35835", "CVE-2024-50017");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2024-053");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.10"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.210-201.852.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.210-201.852-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.210-201.852-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.210-201.852.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.210-201.852.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
