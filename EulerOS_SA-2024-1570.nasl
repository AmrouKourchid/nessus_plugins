#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195280);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2021-33631",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46906",
    "CVE-2021-46928",
    "CVE-2021-46934",
    "CVE-2021-46945",
    "CVE-2021-46952",
    "CVE-2021-46955",
    "CVE-2021-47006",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47040",
    "CVE-2021-47054",
    "CVE-2021-47056",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47074",
    "CVE-2021-47076",
    "CVE-2021-47078",
    "CVE-2021-47082",
    "CVE-2022-48627",
    "CVE-2023-6531",
    "CVE-2023-51042",
    "CVE-2023-51043",
    "CVE-2023-52435",
    "CVE-2023-52439",
    "CVE-2023-52458",
    "CVE-2023-52477",
    "CVE-2023-52486",
    "CVE-2023-52522",
    "CVE-2023-52527",
    "CVE-2023-52528",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2024-0607",
    "CVE-2024-0639",
    "CVE-2024-1086",
    "CVE-2024-1151",
    "CVE-2024-26602"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2024-1570)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: bus: qcom: Put child node before
    return Put child node before return to fix potential reference count leak. Generally, the reference count
    of child is incremented and decremented automatically in the macro for_each_available_child_of_node() and
    should be decremented manually if the loop is broken in loop body.(CVE-2021-47054)

    In the Linux kernel, the following vulnerability has been resolved: i2c: Fix a potential use after free
    Free the adap structure only after we are done using it. This patch just moves the put_device() down a bit
    to avoid the use after free. (CVE-2019-25162)

    In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev-stats fields. Handles updates to
    dev-stats.tx_dropped while we are at it. [1] BUG: KCSAN: data-race in br_handle_frame_finish /
    br_handle_frame_finish read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 1:
    br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220
    br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline]
    br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0
    net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline]
    nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940
    net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417
    __netif_receive_skb_one_core net/core/dev.c:5521 [inline] __netif_receive_skb+0x57/0x1b0
    net/core/dev.c:5637 process_backlog+0x21f/0x380 net/core/dev.c:5965 __napi_poll+0x60/0x3b0
    net/core/dev.c:6527 napi_poll net/core/dev.c:6594 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6727
    __do_softirq+0xc1/0x265 kernel/softirq.c:553 run_ksoftirqd+0x17/0x20 kernel/softirq.c:921
    smpboot_thread_fn+0x30a/0x4a0 kernel/smpboot.c:164 kthread+0x1d7/0x210 kernel/kthread.c:388
    ret_from_fork+0x48/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:304 read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 0:
    br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220
    br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline]
    br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0
    net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline]
    nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940
    net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417
    __netif_receive_skb_one_core net/core/dev.c:5521 [inline] __netif_receive_skb+0x57/0x1b0
    net/core/dev.c:5637 process_backlog+0x21f/0x380 net/core/dev.c:5965 __napi_poll+0x60/0x3b0
    net/core/dev.c:6527 napi_poll net/core/dev.c:6594 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6727
    __do_softirq+0xc1/0x265 kernel/softirq.c:553 do_softirq+0x5e/0x90 kernel/softirq.c:454
    __local_bh_enable_ip+0x64/0x70 kernel/softirq.c:381 __raw_spin_unlock_bh
    include/linux/spinlock_api_smp.h:167 [inline] _raw_spin_unlock_bh+0x36/0x40 kernel/locking/spinlock.c:210
    spin_unlock_bh include/linux/spinlock.h:396 [inline] batadv_tt_local_purge+0x1a8/0x1f0 net/batman-
    adv/translation-table.c:1356 batadv_tt_purge+0x2b/0x630 net/batman-adv/translation-table.c:3560
    process_one_work kernel/workqueue.c:2630 [inline] process_scheduled_works+0x5b8/0xa30
    kernel/workqueue.c:2703 worker_thread+0x525/0x730 kernel/workqueue.c:2784 kthread+0x1d7/0x210
    kernel/kthread.c:388 ret_from_fork+0x48/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:304 value changed: 0x00000000000d7190 - 0x00000000000d7191 Reported by Kernel
    Concurrency Sanitizer on: CPU: 0 PID: 14848 Comm: kworker/u4:11 Not tainted
    6.6.0-rc1-syzkaller-00236-gad8a69f361b9 #0(CVE-2023-52578)

    In the Linux kernel, the following vulnerability has been resolved: net:emac/emac-mac: Fix a use after
    free in emac_mac_tx_buf_send In emac_mac_tx_buf_send, it calls emac_tx_fill_tpd(..,skb,..). If some error
    happens in emac_tx_fill_tpd(), the skb will be freed via dev_kfree_skb(skb) in error branch of
    emac_tx_fill_tpd(). But the freed skb is still used via skb-len by netdev_sent_queue(,skb-len). As i
    observed that emac_tx_fill_tpd() haven't modified the value of skb-len, thus my patch assigns skb-
    len to 'len' before the possible free and use 'len' instead of skb-len later.(CVE-2021-47013)

    In the Linux kernel, the following vulnerability has been resolved: ext4: always panic when errors=panic
    is specified Before commit 014c9caa29d3 ('ext4: make ext4_abort() use __ext4_error()'), the following
    series of commands would trigger a panic: 1. mount /dev/sda -o ro,errors=panic test 2. mount /dev/sda -o
    remount,abort test After commit 014c9caa29d3, remounting a file system using the test mount option 'abort'
    will no longer trigger a panic. This commit will restore the behaviour immediately before commit
    014c9caa29d3. (However, note that the Linux kernel's behavior has not been consistent; some previous
    kernel versions, including 5.4 and 4.19 similarly did not panic after using the mount option 'abort'.)
    This also makes a change to long-standing behaviour; namely, the following series commands will now cause
    a panic, when previously it did not: 1. mount /dev/sda -o ro,errors=panic test 2. echo test 
    /sys/fs/ext4/sda/trigger_fs_error However, this makes ext4's behaviour much more consistent, so this is a
    good thing.(CVE-2021-46945)

    A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality.(CVE-2024-0607)

    A denial of service vulnerability due to a deadlock was found in sctp_auto_asconf_init in
    net/sctp/socket.c in the Linux kernels SCTP subsystem. This flaw allows guests with local user
    privileges to trigger a deadlock and potentially crash the system.(CVE-2024-0639)

    In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

    Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0.(CVE-2021-33631)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit
    f342de4e2f33e0e39165d8639387aa6c19dff660.(CVE-2024-1086)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: smsc75xx: Fix uninit-value
    access in __smsc75xx_read_reg syzbot reported the following uninit-value access issue:
    ===================================================== BUG: KMSAN: uninit-value in smsc75xx_wait_ready
    drivers/net/usb/smsc75xx.c:975 [inline] BUG: KMSAN: uninit-value in smsc75xx_bind+0x5c9/0x11e0
    drivers/net/usb/smsc75xx.c:1482 CPU: 0 PID: 8696 Comm: kworker/0:3 Not tainted 5.8.0-rc5-syzkaller #0
    Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011 Workqueue:
    usb_hub_wq hub_event Call Trace: __dump_stack lib/dump_stack.c:77 [inline] dump_stack+0x21c/0x280
    lib/dump_stack.c:118 kmsan_report+0xf7/0x1e0 mm/kmsan/kmsan_report.c:121 __msan_warning+0x58/0xa0
    mm/kmsan/kmsan_instr.c:215 smsc75xx_wait_ready drivers/net/usb/smsc75xx.c:975 [inline]
    smsc75xx_bind+0x5c9/0x11e0 drivers/net/usb/smsc75xx.c:1482 usbnet_probe+0x1152/0x3f90
    drivers/net/usb/usbnet.c:1737 usb_probe_interface+0xece/0x1550 drivers/usb/core/driver.c:374
    really_probe+0xf20/0x20b0 drivers/base/dd.c:529 driver_probe_device+0x293/0x390 drivers/base/dd.c:701
    __device_attach_driver+0x63f/0x830 drivers/base/dd.c:807 bus_for_each_drv+0x2ca/0x3f0
    drivers/base/bus.c:431 __device_attach+0x4e2/0x7f0 drivers/base/dd.c:873 device_initial_probe+0x4a/0x60
    drivers/base/dd.c:920 bus_probe_device+0x177/0x3d0 drivers/base/bus.c:491 device_add+0x3b0e/0x40d0
    drivers/base/core.c:2680 usb_set_configuration+0x380f/0x3f10 drivers/usb/core/message.c:2032
    usb_generic_driver_probe+0x138/0x300 drivers/usb/core/generic.c:241 usb_probe_device+0x311/0x490
    drivers/usb/core/driver.c:272 really_probe+0xf20/0x20b0 drivers/base/dd.c:529
    driver_probe_device+0x293/0x390 drivers/base/dd.c:701 __device_attach_driver+0x63f/0x830
    drivers/base/dd.c:807 bus_for_each_drv+0x2ca/0x3f0 drivers/base/bus.c:431 __device_attach+0x4e2/0x7f0
    drivers/base/dd.c:873 device_initial_probe+0x4a/0x60 drivers/base/dd.c:920 bus_probe_device+0x177/0x3d0
    drivers/base/bus.c:491 device_add+0x3b0e/0x40d0 drivers/base/core.c:2680 usb_new_device+0x1bd4/0x2a30
    drivers/usb/core/hub.c:2554 hub_port_connect drivers/usb/core/hub.c:5208 [inline] hub_port_connect_change
    drivers/usb/core/hub.c:5348 [inline] port_event drivers/usb/core/hub.c:5494 [inline]
    hub_event+0x5e7b/0x8a70 drivers/usb/core/hub.c:5576 process_one_work+0x1688/0x2140 kernel/workqueue.c:2269
    worker_thread+0x10bc/0x2730 kernel/workqueue.c:2415 kthread+0x551/0x590 kernel/kthread.c:292
    ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:293 Local variable ----buf.i87@smsc75xx_bind created at:
    __smsc75xx_read_reg drivers/net/usb/smsc75xx.c:83 [inline] smsc75xx_wait_ready
    drivers/net/usb/smsc75xx.c:968 [inline] smsc75xx_bind+0x485/0x11e0 drivers/net/usb/smsc75xx.c:1482
    __smsc75xx_read_reg drivers/net/usb/smsc75xx.c:83 [inline] smsc75xx_wait_ready
    drivers/net/usb/smsc75xx.c:968 [inline] smsc75xx_bind+0x485/0x11e0 drivers/net/usb/smsc75xx.c:1482 This
    issue is caused because usbnet_read_cmd() reads less bytes than requested (zero byte in the reproducer).
    In this case, 'buf' is not properly filled. This patch fixes the issue by returning -ENODATA if
    usbnet_read_cmd() reads less bytes than requested.(CVE-2023-52528)

    In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has
    a fence use-after-free.(CVE-2023-51042)

    In the Linux kernel, the following vulnerability has been resolved: uio: Fix use-after-free in uio_open
    core-1 core-2 ------------------------------------------------------- uio_unregister_device uio_open idev
    = idr_find() device_unregister(idev-dev) put_device(idev-dev) uio_device_release
    get_device(idev-dev) kfree(idev) uio_free_minor(minor) uio_release put_device(idev-dev)
    kfree(idev) ------------------------------------------------------- In the core-1 uio_unregister_device(),
    the device_unregister will kfree idev when the idev-dev kobject ref is 1. But after core-1
    device_unregister, put_device and before doing kfree, the core-2 may get_device. Then: 1. After core-1
    kfree idev, the core-2 will do use-after-free for idev. 2. When core-2 do uio_release and put_device, the
    idev will be double freed. To address this issue, we can get idev atomic  inc idev reference with
    minor_lock.(CVE-2023-52439)

    In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in
    skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a
    forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily :
    mss = mss * partial_segs; 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final
    result. Make sure to limit segmentation so that the new mss value is smaller than GSO_BY_FRAGS. [1]
    general protection fault, probably for non-canonical address 0xdffffc000000000e: 0000 [#1] PREEMPT SMP
    KASAN KASAN: null-ptr-deref in range [0x0000000000000070-0x0000000000000077] CPU: 1 PID: 5079 Comm: syz-
    executor993 Not tainted 6.7.0-rc4-syzkaller-00141-g1ae4cd3cbdd0 #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 11/10/2023 RIP: 0010:skb_segment+0x181d/0x3f30
    net/core/skbuff.c:4551 Code: 83 e3 02 e9 fb ed ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48
    b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 0f b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48
    8b 84 24 f8 00 RSP: 0018:ffffc900043473d0 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000010046
    RCX: ffffffff886b1597 RDX: 000000000000000e RSI: ffffffff886b2520 RDI: 0000000000000070 RBP:
    ffffc90004347578 R08: 0000000000000005 R09: 000000000000ffff R10: 000000000000ffff R11: 0000000000000002
    R12: ffff888063202ac0 R13: 0000000000010000 R14: 000000000000ffff R15: 0000000000000046 FS:
    0000555556e7e380(0000) GS:ffff8880b9900000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 0000000020010000 CR3: 0000000027ee2000 CR4: 00000000003506f0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: TASK udp6_ufo_fragment+0xa0e/0xd00 net/ipv6/udp_offload.c:109
    ipv6_gso_segment+0x534/0x17e0 net/ipv6/ip6_offload.c:120 skb_mac_gso_segment+0x290/0x610 net/core/gso.c:53
    __skb_gso_segment+0x339/0x710 net/core/gso.c:124 skb_gso_segment include/net/gso.h:83 [inline]
    validate_xmit_skb+0x36c/0xeb0 net/core/dev.c:3626 __dev_queue_xmit+0x6f3/0x3d60 net/core/dev.c:4338
    dev_queue_xmit include/linux/netdevice.h:3134 [inline] packet_xmit+0x257/0x380 net/packet/af_packet.c:276
    packet_snd net/packet/af_packet.c:3087 [inline] packet_sendmsg+0x24c6/0x5220 net/packet/af_packet.c:3119
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0xd5/0x180 net/socket.c:745
    __sys_sendto+0x255/0x340 net/socket.c:2190 __do_sys_sendto net/socket.c:2202 [inline] __se_sys_sendto
    net/socket.c:2198 [inline] __x64_sys_sendto+0xe0/0x1b0 net/socket.c:2198 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x40/0x110 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b RIP: 0033:0x7f8692032aa9 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 d1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 48 3d
    01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fff8d685418 EFLAGS: 00000246
    ORIG_RAX: 000000000000002c RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00007f8692032aa9 RDX:
    0000000000010048 RSI: 00000000200000c0 RDI: 0000000000000003 RBP: 00000000000f4240 R08: 0000000020000540
    R09: 0000000000000014 R10: 0000000000000000 R11: 0000000000000246 R12: 00007fff8d685480 R13:
    0000000000000001 R14: 00007fff8d685480 R15: 0000000000000003 /TASK Modules linked in: ---[ end trace
    0000000000000000 ]--- RIP: 0010:skb_segment+0x181d/0x3f30 net/core/skbuff.c:4551 Code: 83 e3 02 e9 fb ed
    ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea
    03 0f b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48 8b 84 24 f8 00 RSP: 0018:ffffc900043473d0
    EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000010046 RCX: ffffffff886b1597 RDX: 000000000000000e
    RSI: ffffffff886b2520 RDI: 0000000000000070 RBP: ffffc90004347578 R0 ---truncated---(CVE-2023-52435)

    In the Linux kernel, the following vulnerability has been resolved: parisc: Clear stale IIR value on
    instruction access rights trap When a trap 7 (Instruction access rights) occurs, this means the CPU
    couldn't execute an instruction due to missing execute permissions on the memory region. In this case it
    seems the CPU didn't even fetched the instruction from memory and thus did not store it in the cr19 (IIR)
    register before calling the trap handler. So, the trap handler will find some random old stale value in
    cr19. This patch simply overwrites the stale IIR value with a constant magic 'bad food' value
    (0xbaadf00d), in the hope people don't start to try to understand the various random IIR values in trap 7
    dumps.(CVE-2021-46928)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Destroy I/O bus devices on
    unregister failure _after_ sync'ing SRCU If allocating a new instance of an I/O bus fails when
    unregistering a device, wait to destroy the device until after all readers are guaranteed to see the new
    null bus. Destroying devices before the bus is nullified could lead to use-after-free since readers expect
    the devices on their reference of the bus to remain valid.(CVE-2021-47061)

    In the Linux kernel, the following vulnerability has been resolved: net: hso: fix null-ptr-deref during
    tty device unregistration Multiple ttys try to claim the same the minor number causing a double
    unregistration of the same device. The first unregistration succeeds but the next one results in a null-
    ptr-deref. The get_free_serial_index() function returns an available minor number but doesn't assign it
    immediately. The assignment is done by the caller later. But before this assignment, calls to
    get_free_serial_index() would return the same minor number. Fix this by modifying get_free_serial_index to
    assign the minor number immediately after one is found to be and rename it to obtain_minor() to better
    reflect what it does. Similary, rename set_serial_by_index() to release_minor() and modify it to free up
    the minor number of the given hso_serial. Every obtain_minor() should have corresponding release_minor()
    call.(CVE-2021-46904)

    In the Linux kernel, the following vulnerability has been resolved: net: hso: fix NULL-deref on disconnect
    regression Commit 8a12f8836145 ('net: hso: fix null-ptr-deref during tty device unregistration') fixed the
    racy minor allocation reported by syzbot, but introduced an unconditional NULL-pointer dereference on
    every disconnect instead. Specifically, the serial device table must no longer be accessed after the minor
    has been released by hso_serial_tty_unregister().(CVE-2021-46905)

    In the Linux kernel, the following vulnerability has been resolved: openvswitch: fix stack OOB read while
    fragmenting IPv4 packets running openvswitch on kernels built with KASAN, it's possible to see the
    following splat while testing fragmentation of IPv4 packets: BUG: KASAN: stack-out-of-bounds in
    ip_do_fragment+0x1b03/0x1f60 Read of size 1 at addr ffff888112fc713c by task handler2/1367 CPU: 0 PID:
    1367 Comm: handler2 Not tainted 5.12.0-rc6+ #418 Hardware name: Red Hat KVM, BIOS
    1.11.1-4.module+el8.1.0+4066+0f1aadab 04/01/2014 Call Trace: dump_stack+0x92/0xc1
    print_address_description.constprop.7+0x1a/0x150 kasan_report.cold.13+0x7f/0x111
    ip_do_fragment+0x1b03/0x1f60 ovs_fragment+0x5bf/0x840 [openvswitch] do_execute_actions+0x1bd5/0x2400
    [openvswitch] ovs_execute_actions+0xc8/0x3d0 [openvswitch] ovs_packet_cmd_execute+0xa39/0x1150
    [openvswitch] genl_family_rcv_msg_doit.isra.15+0x227/0x2d0 genl_rcv_msg+0x287/0x490
    netlink_rcv_skb+0x120/0x380 genl_rcv+0x24/0x40 netlink_unicast+0x439/0x630 netlink_sendmsg+0x719/0xbf0
    sock_sendmsg+0xe2/0x110 ____sys_sendmsg+0x5ba/0x890 ___sys_sendmsg+0xe9/0x160 __sys_sendmsg+0xd3/0x170
    do_syscall_64+0x33/0x40 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f957079db07 Code: c3 66 90
    41 54 41 89 d4 55 48 89 f5 53 89 fb 48 83 ec 10 e8 eb ec ff ff 44 89 e2 48 89 ee 89 df 41 89 c0 b8 2e 00
    00 00 0f 05 48 3d 00 f0 ff ff 77 35 44 89 c7 48 89 44 24 08 e8 24 ed ff ff 48 RSP:
    002b:00007f956ce35a50 EFLAGS: 00000293 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX:
    0000000000000019 RCX: 00007f957079db07 RDX: 0000000000000000 RSI: 00007f956ce35ae0 RDI: 0000000000000019
    RBP: 00007f956ce35ae0 R08: 0000000000000000 R09: 00007f9558006730 R10: 0000000000000000 R11:
    0000000000000293 R12: 0000000000000000 R13: 00007f956ce37308 R14: 00007f956ce35f80 R15: 00007f956ce35ae0
    The buggy address belongs to the page: page:00000000af2a1d93 refcount:0 mapcount:0
    mapping:0000000000000000 index:0x0 pfn:0x112fc7 flags: 0x17ffffc0000000() raw: 0017ffffc0000000
    0000000000000000 dead000000000122 0000000000000000 raw: 0000000000000000 0000000000000000 00000000ffffffff
    0000000000000000 page dumped because: kasan: bad access detected addr ffff888112fc713c is located in stack
    of task handler2/1367 at offset 180 in frame: ovs_fragment+0x0/0x840 [openvswitch] this frame has 2
    objects: [32, 144) 'ovs_dst' [192, 424) 'ovs_rt' Memory state around the buggy address: ffff888112fc7000:
    f3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ffff888112fc7080: 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
    00 00 00 ffff888112fc7100: 00 00 00 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 ^ ffff888112fc7180: 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 ffff888112fc7200: 00 00 00 00 00 00 f2 f2 f2 00 00 00 00 00 00 00
    for IPv4 packets, ovs_fragment() uses a temporary struct dst_entry. Then, in the following call graph:
    ip_do_fragment() ip_skb_dst_mtu() ip_dst_mtu_maybe_forward() ip_mtu_locked() the pointer to struct
    dst_entry is used as pointer to struct rtable: this turns the access to struct members like rt_mtu_locked
    into an OOB read in the stack. Fix this changing the temporary variable used for IPv4 packets in
    ovs_fragment(), similarly to what is done for IPv6 few lines below.(CVE-2021-46955)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: nvme-loop: fix memory leak in
    nvme_loop_create_ctrl() When creating loop ctrl in nvme_loop_create_ctrl(), if nvme_init_ctrl() fails, the
    loop ctrl should be freed before jumping to the 'out' label.(CVE-2021-47074)

    In the Linux kernel, the following vulnerability has been resolved: crypto: qat - ADF_STATUS_PF_RUNNING
    should be set after adf_dev_init ADF_STATUS_PF_RUNNING is (only) used and checked by adf_vf2pf_shutdown()
    before calling adf_iov_putmsg()-mutex_lock(vf2pf_lock), however the vf2pf_lock is initialized in
    adf_dev_init(), which can fail and when it fail, the vf2pf_lock is either not initialized or destroyed, a
    subsequent use of vf2pf_lock will cause issue. To fix this issue, only set this flag if adf_dev_init()
    returns 0. [ 7.178404] BUG: KASAN: user-memory-access in __mutex_lock.isra.(CVE-2021-47056)

    In the Linux kernel, the following vulnerability has been resolved: usb: hub: Guard against accesses to
    uninitialized BOS descriptors Many functions in drivers/usb/core/hub.c and drivers/usb/core/hub.h access
    fields inside udev-bos without checking if it was allocated and initialized. If
    usb_get_bos_descriptor() fails for whatever reason, udev-bos will be NULL and those accesses will
    result in a crash: BUG: kernel NULL pointer dereference, address: 0000000000000018 PGD 0 P4D 0 Oops: 0000
    [#1] PREEMPT SMP NOPTI CPU: 5 PID: 17818 Comm: kworker/5:1 Tainted: G W 5.15.108-18910-gab0e1cb584e1 #1
    HASH:1f9e 1 Hardware name: Google Kindred/Kindred, BIOS Google_Kindred.12672.413.0 02/03/2021
    Workqueue: usb_hub_wq hub_event RIP: 0010:hub_port_reset+0x193/0x788 Code: 89 f7 e8 20 f7 15 00 48 8b 43
    08 80 b8 96 03 00 00 03 75 36 0f b7 88 92 03 00 00 81 f9 10 03 00 00 72 27 48 8b 80 a8 03 00 00 48
    83 78 18 00 74 19 48 89 df 48 8b 75 b0 ba 02 00 00 00 4c 89 e9 RSP: 0018:ffffab740c53fcf8 EFLAGS: 00010246
    RAX: 0000000000000000 RBX: ffffa1bc5f678000 RCX: 0000000000000310 RDX: fffffffffffffdff RSI:
    0000000000000286 RDI: ffffa1be9655b840 RBP: ffffab740c53fd70 R08: 00001b7d5edaa20c R09: ffffffffb005e060
    R10: 0000000000000001 R11: 0000000000000000 R12: 0000000000000000 R13: ffffab740c53fd3e R14:
    0000000000000032 R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffffa1be96540000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000018 CR3:
    000000022e80c005 CR4: 00000000003706e0 Call Trace: hub_event+0x73f/0x156e ? hub_activate+0x5b7/0x68f
    process_one_work+0x1a2/0x487 worker_thread+0x11a/0x288 kthread+0x13a/0x152 ? process_one_work+0x487/0x487
    ? kthread_associate_blkcg+0x70/0x70 ret_from_fork+0x1f/0x30 Fall back to a default behavior if the BOS
    descriptor isn't accessible and skip all the functionalities that depend on it: LPM support checks, Super
    Speed capabilitiy checks, U1/U2 states setup.(CVE-2023-52477)

    A use-after-free flaw was found in the Linux Kernel due to a race problem in the unix garbage collector's
    deletion of SKB races with unix_stream_read_generic() on the socket that the SKB is queued
    on.(CVE-2023-6531)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Return CQE error if invalid
    lkey was supplied RXE is missing update of WQE status in LOCAL_WRITE failures. This caused the following
    kernel panic if someone sent an atomic operation with an explicitly wrong lkey. [leonro@vm ~]$ mkt test
    test_atomic_invalid_lkey (tests.test_atomic.AtomicTest) ... WARNING: CPU: 5 PID: 263 at
    drivers/infiniband/sw/rxe/rxe_comp.c:740 rxe_completer+0x1a6d/0x2e30 [rdma_rxe] Modules linked in:
    crc32_generic rdma_rxe ip6_udp_tunnel udp_tunnel rdma_ucm rdma_cm ib_umad ib_ipoib iw_cm ib_cm mlx5_ib
    ib_uverbs ib_core mlx5_core ptp pps_core CPU: 5 PID: 263 Comm: python3 Not tainted 5.13.0-rc1+ #2936
    Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org
    04/01/2014 RIP: 0010:rxe_completer+0x1a6d/0x2e30 [rdma_rxe] Code: 03 0f 8e 65 0e 00 00 3b 93 10 06 00 00
    0f 84 82 0a 00 00 4c 89 ff 4c 89 44 24 38 e8 2d 74 a9 e1 4c 8b 44 24 38 e9 1c f5 ff ff 0f 0b e9 0c
    e8 ff ff b8 05 00 00 00 41 bf 05 00 00 00 e9 ab e7 ff RSP: 0018:ffff8880158af090 EFLAGS: 00010246 RAX:
    0000000000000000 RBX: ffff888016a78000 RCX: ffffffffa0cf1652 RDX: 1ffff9200004b442 RSI: 0000000000000004
    RDI: ffffc9000025a210 RBP: dffffc0000000000 R08: 00000000ffffffea R09: ffff88801617740b R10:
    ffffed1002c2ee81 R11: 0000000000000007 R12: ffff88800f3b63e8 R13: ffff888016a78008 R14: ffffc9000025a180
    R15: 000000000000000c FS: 00007f88b622a740(0000) GS:ffff88806d540000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f88b5a1fa10 CR3: 000000000d848004 CR4: 0000000000370ea0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 Call Trace: rxe_do_task+0x130/0x230 [rdma_rxe] rxe_rcv+0xb11/0x1df0
    [rdma_rxe] rxe_loopback+0x157/0x1e0 [rdma_rxe] rxe_responder+0x5532/0x7620 [rdma_rxe]
    rxe_do_task+0x130/0x230 [rdma_rxe] rxe_rcv+0x9c8/0x1df0 [rdma_rxe] rxe_loopback+0x157/0x1e0 [rdma_rxe]
    rxe_requester+0x1efd/0x58c0 [rdma_rxe] rxe_do_task+0x130/0x230 [rdma_rxe] rxe_post_send+0x998/0x1860
    [rdma_rxe] ib_uverbs_post_send+0xd5f/0x1220 [ib_uverbs] ib_uverbs_write+0x847/0xc80 [ib_uverbs]
    vfs_write+0x1c5/0x840 ksys_write+0x176/0x1d0 do_syscall_64+0x3f/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae(CVE-2021-47076)

    In the Linux kernel, the following vulnerability has been resolved: sched/membarrier: reduce the ability
    to hammer on sys_membarrier On some systems, sys_membarrier can be very expensive, causing overall
    slowdowns for everything. So put a lock on the path in order to serialize the accesses to prevent the
    ability for this to be called at too high of a frequency and saturate the machine.(CVE-2024-26602)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Clear all QP fields if
    creation failed rxe_qp_do_cleanup() relies on valid pointer values in QP for the properly created ones,
    but in case rxe_qp_from_init() failed it was filled with garbage and caused tot the following error.
    refcount_t: underflow; use-after-free. WARNING: CPU: 1 PID: 12560 at lib/refcount.c:28
    refcount_warn_saturate+0x1d1/0x1e0 lib/refcount.c:28 Modules linked in: CPU: 1 PID: 12560 Comm: syz-
    executor.4 Not tainted 5.12.0-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/01/2011 RIP: 0010:refcount_warn_saturate+0x1d1/0x1e0 lib/refcount.c:28 Code: e9 db
    fe ff ff 48 89 df e8 2c c2 ea fd e9 8a fe ff ff e8 72 6a a7 fd 48 c7 c7 e0 b2 c1 89 c6 05 dc 3a e6 09 01
    e8 ee 74 fb 04 0f 0b e9 af fe ff ff 0f 1f 84 00 00 00 00 00 41 56 41 55 41 54 55 RSP:
    0018:ffffc900097ceba8 EFLAGS: 00010286 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
    RDX: 0000000000040000 RSI: ffffffff815bb075 RDI: fffff520012f9d67 RBP: 0000000000000003 R08:
    0000000000000000 R09: 0000000000000000 R10: ffffffff815b4eae R11: 0000000000000000 R12: ffff8880322a4800
    R13: ffff8880322a4940 R14: ffff888033044e00 R15: 0000000000000000 FS: 00007f6eb2be3700(0000)
    GS:ffff8880b9d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007fdbe5d41000 CR3: 000000001d181000 CR4: 00000000001506e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace:
    __refcount_sub_and_test include/linux/refcount.h:283 [inline] __refcount_dec_and_test
    include/linux/refcount.h:315 [inline] refcount_dec_and_test include/linux/refcount.h:333 [inline] kref_put
    include/linux/kref.h:64 [inline] rxe_qp_do_cleanup+0x96f/0xaf0 drivers/infiniband/sw/rxe/rxe_qp.c:805
    execute_in_process_context+0x37/0x150 kernel/workqueue.c:3327 rxe_elem_release+0x9f/0x180
    drivers/infiniband/sw/rxe/rxe_pool.c:391 kref_put include/linux/kref.h:65 [inline]
    rxe_create_qp+0x2cd/0x310 drivers/infiniband/sw/rxe/rxe_verbs.c:425 _ib_create_qp
    drivers/infiniband/core/core_priv.h:331 [inline] ib_create_named_qp+0x2ad/0x1370
    drivers/infiniband/core/verbs.c:1231 ib_create_qp include/rdma/ib_verbs.h:3644 [inline]
    create_mad_qp+0x177/0x2d0 drivers/infiniband/core/mad.c:2920 ib_mad_port_open
    drivers/infiniband/core/mad.c:3001 [inline] ib_mad_init_device+0xd6f/0x1400
    drivers/infiniband/core/mad.c:3092 add_client_context+0x405/0x5e0 drivers/infiniband/core/device.c:717
    enable_device_and_get+0x1cd/0x3b0 drivers/infiniband/core/device.c:1331 ib_register_device
    drivers/infiniband/core/device.c:1413 [inline] ib_register_device+0x7c7/0xa50
    drivers/infiniband/core/device.c:1365 rxe_register_device+0x3d5/0x4a0
    drivers/infiniband/sw/rxe/rxe_verbs.c:1147 rxe_add+0x12fe/0x16d0 drivers/infiniband/sw/rxe/rxe.c:247
    rxe_net_add+0x8c/0xe0 drivers/infiniband/sw/rxe/rxe_net.c:503 rxe_newlink
    drivers/infiniband/sw/rxe/rxe.c:269 [inline] rxe_newlink+0xb7/0xe0 drivers/infiniband/sw/rxe/rxe.c:250
    nldev_newlink+0x30e/0x550 drivers/infiniband/core
    ldev.c:1555 rdma_nl_rcv_msg+0x36d/0x690 drivers/infiniband/core
    etlink.c:195 rdma_nl_rcv_skb drivers/infiniband/core
    etlink.c:239 [inline] rdma_nl_rcv+0x2ee/0x430 drivers/infiniband/core
    etlink.c:259 netlink_unicast_kernel net
    etlink/af_netlink.c:1312 [inline] netlink_unicast+0x533/0x7d0 net
    etlink/af_netlink.c:1338 netlink_sendmsg+0x856/0xd90 net
    etlink/af_netlink.c:1927 sock_sendmsg_nosec net/socket.c:654 [inline] sock_sendmsg+0xcf/0x120
    net/socket.c:674 ____sys_sendmsg+0x6e8/0x810 net/socket.c:2350 ___sys_sendmsg+0xf3/0x170 net/socket.c:2404
    __sys_sendmsg+0xe5/0x1b0 net/socket.c:2433 do_syscall_64+0x3a/0xb0 arch/x86/entry/common.c:47
    entry_SYSCALL_64_after_hwframe+0 ---truncated---(CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved: HID: usbhid: fix info leak in
    hid_submit_ctrl In hid_submit_ctrl(), the way of calculating the report length doesn't take into account
    that report-size can be zero. When running the syzkaller reproducer, a report of size 0 causes
    hid_submit_ctrl) to calculate transfer_buffer_length as 16384. When this urb is passed to the usb core
    layer, KMSAN reports an info leak of 16384 bytes. To fix this, first modify hid_report_len() to account
    for the zero report size case by using DIV_ROUND_UP for the division. Then, call it from
    hid_submit_ctrl().(CVE-2021-46906)

    In the Linux kernel, the following vulnerability has been resolved: drm: Don't unref the same fb many
    times by mistake due to deadlock handling If we get a deadlock after the fb lookup in
    drm_mode_page_flip_ioctl() we proceed to unref the fb and then retry the whole thing from the top. But we
    forget to reset the fb pointer back to NULL, and so if we then get another error during the retry, before
    the fb lookup, we proceed the unref the same fb again without having gotten another reference. The end
    result is that the fb will (eventually) end up being freed while it's still in use. Reset fb to NULL once
    we've unreffed it to avoid doing it again until we've done another fb lookup. This turned out to be pretty
    easy to hit on a DG2 when doing async flips (and CONFIG_DEBUG_WW_MUTEX_SLOWPATH=y). The first symptom I
    saw that drm_closefb() simply got stuck in a busy loop while walking the framebuffer list. Fortunately I
    was able to convince it to oops instead, and from there it was easier to track down the
    culprit.(CVE-2023-52486)

    In the Linux kernel, the following vulnerability has been resolved: drm: bridge/panel: Cleanup connector
    on bridge detach If we don't call drm_connector_cleanup() manually in panel_bridge_detach(), the connector
    will be cleaned up with the other DRM objects in the call to drm_mode_config_cleanup(). However, since our
    drm_connector is devm-allocated, by the time drm_mode_config_cleanup() will be called, our connector will
    be long gone. Therefore, the connector must be cleaned up when the bridge is detached to avoid use-after-
    free conditions.(CVE-2021-47063)

    In the Linux kernel, the following vulnerability has been resolved: ceph: fix deadlock or deadcode of
    misusing dget() The lock order is incorrect between denty and its parent, we should always make sure that
    the parent get the lock first. But since this deadcode is never used and the parent dir will always be set
    from the callers, let's just remove it.(CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved: ARM: 9064/1: hw_breakpoint: Do not
    directly check the event's overflow_handler hook The commit 1879445dfa7b ('perf/core: Set event's default
    ::overflow_handler()') set a default event-overflow_handler in perf_event_alloc(), and replace the
    check event-overflow_handler with is_default_overflow_handler(), but one is missing. Currently, the bp-
    overflow_handler can not be NULL. As a result, enable_single_step() is always not invoked. Comments
    from Zhen Lei: https://patchwork.kernel.org/project/linux-arm-
    kernel/patch/20210207105934.2001-1-thunder.leizhen@huawei.com/(CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved: net: fix possible store tearing in
    neigh_periodic_work() While looking at a related syzbot report involving neigh_periodic_work(), I found
    that I forgot to add an annotation when deleting an RCU protected item from a list. Readers use
    rcu_deference(*np), we need to use either rcu_assign_pointer() or WRITE_ONCE() on writer side to prevent
    store tearing. I use rcu_assign_pointer() to have lockdep support, this was the choice made in
    neigh_flush_dev().(CVE-2023-52522)

    In the Linux kernel, the following vulnerability has been resolved:vt: fix memory overlapping when
    deleting chars in the buffer.A memory overlapping copy occurs when deleting a long line. This memory
    overlapping copy can cause data corruption when scr_memcpyw is optimized to memcpy because memcpy does not
    ensure its behavior if the destination buffer overlaps with the source buffer. The line buffer is not
    always broken, because the memcpy utilizes the hardware acceleration, whose result is not
    deterministic.Fix this problem by using replacing the scr_memcpyw with scr_memmovew.(CVE-2022-48627)

    In the Linux kernel, the following vulnerability has been resolved: bnxt_en: Fix RX consumer index logic
    in the error path. In bnxt_rx_pkt(), the RX buffers are expected to complete in order. If the RX consumer
    index indicates an out of order buffer completion, it means we are hitting a hardware bug and the driver
    will abort all remaining RX packets and reset the RX ring. The RX consumer index that we pass to
    bnxt_discard_rx() is not correct. We should be passing the current index (tmp_raw_cons) instead of the old
    index (raw_cons). This bug can cause us to be at the wrong index when trying to abort the next RX packet.
    It can crash like this: #0 [ffff9bbcdf5c39a8] machine_kexec at ffffffff9b05e007 #1 [ffff9bbcdf5c3a00]
    __crash_kexec at ffffffff9b111232 #2 [ffff9bbcdf5c3ad0] panic at ffffffff9b07d61e #3 [ffff9bbcdf5c3b50]
    oops_end at ffffffff9b030978 #4 [ffff9bbcdf5c3b78] no_context at ffffffff9b06aaf0 #5 [ffff9bbcdf5c3bd8]
    __bad_area_nosemaphore at ffffffff9b06ae2e #6 [ffff9bbcdf5c3c28] bad_area_nosemaphore at ffffffff9b06af24
    #7 [ffff9bbcdf5c3c38] __do_page_fault at ffffffff9b06b67e #8 [ffff9bbcdf5c3cb0] do_page_fault at
    ffffffff9b06bb12 #9 [ffff9bbcdf5c3ce0] page_fault at ffffffff9bc015c5 [exception RIP: bnxt_rx_pkt+237]
    RIP: ffffffffc0259cdd RSP: ffff9bbcdf5c3d98 RFLAGS: 00010213 RAX: 000000005dd8097f RBX: ffff9ba4cb11b7e0
    RCX: ffffa923cf6e9000 RDX: 0000000000000fff RSI: 0000000000000627 RDI: 0000000000001000 RBP:
    ffff9bbcdf5c3e60 R8: 0000000000420003 R9: 000000000000020d R10: ffffa923cf6ec138 R11: ffff9bbcdf5c3e83
    R12: ffff9ba4d6f928c0 R13: ffff9ba4cac28080 R14: ffff9ba4cb11b7f0 R15: ffff9ba4d5a30000 ORIG_RAX:
    ffffffffffffffff CS: 0010 SS: 0018(CVE-2021-47015)

    In the Linux kernel, the following vulnerability has been resolved: vsock/virtio: free queued packets when
    closing socket As reported by syzbot [1], there is a memory leak while closing the socket. We partially
    solved this issue with commit ac03046ece2b ('vsock/virtio: free packets during the socket release'), but
    we forgot to drain the RX queue when the socket is definitely closed by the scheduled work. To avoid
    future issues, let's use the new virtio_transport_remove_sock() to drain the RX queue before removing the
    socket from the af_vsock lists calling vsock_remove_sock().(CVE-2021-47024)

    In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in
    tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev-tstats and tun-security
    allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is
    paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the
    destructor will handle the frees. BUG: KASAN: double-free or invalid-free in
    selinux_tun_dev_free_security+0x1a/0x20 security/selinux/hooks.c:5605 CPU: 0 PID: 25750 Comm: syz-
    executor416 Not tainted 5.16.0-rc2-syzk #1 Hardware name: Red Hat KVM, BIOS Call Trace: TASK
    __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x89/0xb5 lib/dump_stack.c:106
    print_address_description.constprop.9+0x28/0x160 mm/kasan/report.c:247 kasan_report_invalid_free+0x55/0x80
    mm/kasan/report.c:372 ____kasan_slab_free mm/kasan/common.c:346 [inline] __kasan_slab_free+0x107/0x120
    mm/kasan/common.c:374 kasan_slab_free include/linux/kasan.h:235 [inline] slab_free_hook mm/slub.c:1723
    [inline] slab_free_freelist_hook mm/slub.c:1749 [inline] slab_free mm/slub.c:3513 [inline]
    kfree+0xac/0x2d0 mm/slub.c:4561 selinux_tun_dev_free_security+0x1a/0x20 security/selinux/hooks.c:5605
    security_tun_dev_free_security+0x4f/0x90 security/security.c:2342 tun_free_netdev+0xe6/0x150 drivers
    et/tun.c:2215 netdev_run_todo+0x4df/0x840 net/core/dev.c:10627 rtnl_unlock+0x13/0x20
    net/core/rtnetlink.c:112 __tun_chr_ioctl+0x80c/0x2870 drivers
    et/tun.c:3302 tun_chr_ioctl+0x2f/0x40 drivers
    et/tun.c:3311 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:874 [inline] __se_sys_ioctl
    fs/ioctl.c:860 [inline] __x64_sys_ioctl+0x19d/0x220 fs/ioctl.c:860 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3a/0x80 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae(CVE-2021-47082)

    In the Linux kernel, the following vulnerability has been resolved: NFS: fs_context: validate UDP retrans
    to prevent shift out-of-bounds Fix shift out-of-bounds in xprt_calc_majortimeo(). This is caused by a
    garbage timeout (retrans) mount option being passed to nfs mount, in this case from syzkaller. If the
    protocol is XPRT_TRANSPORT_UDP, then 'retrans' is a shift value for a 64-bit long integer, so 'retrans'
    cannot be = 64. If it is = 64, fail the mount and return an error.(CVE-2021-46952)

    In the Linux kernel, the following vulnerability has been resolved: io_uring: fix overflows checks in
    provide buffers Colin reported before possible overflow and sign extension problems in
    io_provide_buffers_prep(). As Linus pointed out previous attempt did nothing useful, see d81269fecb8ce
    ('io_uring: fix provide_buffers sign extension'). Do that with help of check_op_overflow helpers.
    And fix struct io_provide_buf::len type, as it doesn't make much sense to keep it signed.(CVE-2021-47040)

    In the Linux kernel, the following vulnerability has been resolved: ipv4, ipv6: Fix handling of
    transhdrlen in __ip{,6}_append_data() Including the transhdrlen in length is a problem when the packet is
    partially filled (e.g. something like send(MSG_MORE) happened previously) when appending to an IPv4 or
    IPv6 packet as we don't want to repeat the transport header or account for it twice. This can happen under
    some circumstances, such as splicing into an L2TP socket. The symptom observed is a warning in
    __ip6_append_data(): WARNING: CPU: 1 PID: 5042 at net/ipv6/ip6_output.c:1800
    __ip6_append_data.isra.0+0x1be8/0x47f0 net/ipv6/ip6_output.c:1800 that occurs when MSG_SPLICE_PAGES is
    used to append more data to an already partially occupied skbuff. The warning occurs when 'copy' is larger
    than the amount of data in the message iterator. This is because the requested length includes the
    transport header length when it shouldn't. This can be triggered by, for example: sfd = socket(AF_INET6,
    SOCK_DGRAM, IPPROTO_L2TP); bind(sfd, ...); // ::1 connect(sfd, ...); // ::1 port 7 send(sfd, buffer, 4100,
    MSG_MORE); sendfile(sfd, dfd, NULL, 1024); Fix this by only adding transhdrlen into the length if the
    write queue is empty in l2tp_ip6_sendmsg(), analogously to how UDP does things. l2tp_ip_sendmsg() looks
    like it won't suffer from this problem as it builds the UDP packet itself.(CVE-2023-52527)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1570
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e322bbd5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2211.3.0.h1746.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2211.3.0.h1746.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2211.3.0.h1746.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2211.3.0.h1746.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2211.3.0.h1746.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
