#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202959);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2021-33631",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46906",
    "CVE-2021-46915",
    "CVE-2021-46921",
    "CVE-2021-46928",
    "CVE-2021-46932",
    "CVE-2021-46934",
    "CVE-2021-46936",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46945",
    "CVE-2021-46952",
    "CVE-2021-46953",
    "CVE-2021-46955",
    "CVE-2021-46960",
    "CVE-2021-46988",
    "CVE-2021-46992",
    "CVE-2021-47006",
    "CVE-2021-47010",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47054",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47074",
    "CVE-2021-47076",
    "CVE-2021-47077",
    "CVE-2021-47078",
    "CVE-2021-47082",
    "CVE-2021-47091",
    "CVE-2021-47101",
    "CVE-2021-47131",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47146",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47182",
    "CVE-2021-47194",
    "CVE-2021-47203",
    "CVE-2022-48619",
    "CVE-2022-48627",
    "CVE-2023-7042",
    "CVE-2023-51042",
    "CVE-2023-51043",
    "CVE-2023-52340",
    "CVE-2023-52435",
    "CVE-2023-52439",
    "CVE-2023-52458",
    "CVE-2023-52464",
    "CVE-2023-52469",
    "CVE-2023-52477",
    "CVE-2023-52478",
    "CVE-2023-52486",
    "CVE-2023-52515",
    "CVE-2023-52522",
    "CVE-2023-52527",
    "CVE-2023-52528",
    "CVE-2023-52530",
    "CVE-2023-52574",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2024-0607",
    "CVE-2024-0775",
    "CVE-2024-1086",
    "CVE-2024-1151",
    "CVE-2024-23307",
    "CVE-2024-24855",
    "CVE-2024-25739",
    "CVE-2024-26597",
    "CVE-2024-26598",
    "CVE-2024-26602",
    "CVE-2024-26614",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26645",
    "CVE-2024-26668",
    "CVE-2024-26671",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26686",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26752",
    "CVE-2024-26759",
    "CVE-2024-26763",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26779",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26828",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26851",
    "CVE-2024-26859",
    "CVE-2024-26872",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26894",
    "CVE-2024-26901",
    "CVE-2024-26915",
    "CVE-2024-26922",
    "CVE-2024-27437"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2024-2038)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking
    Releasing the `priv-lock` while iterating the `priv-multicast_list` in `ipoib_mcast_join_task()`
    opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the
    mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard
    lockup(CVE-2023-52587)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nftables: avoid overflows
    in nft_hash_buckets() Number of buckets being stored in 32bit variables, we have to ensure that no
    overflows occur in nft_hash_buckets() syzbot injected a size == 0x40000000 and reported: UBSAN: shift-out-
    of-bounds in ./include/linux/log2.h:57:13 shift exponent 64 is too large for 64-bit type 'long unsigned
    int' CPU: 1 PID: 29539 Comm: syz-executor.4 Not tainted 5.12.0-rc7-syzkaller #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011(CVE-2021-46992)

    In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage
    warning I received the following warning while running cthon against an ontap server running pNFS: [
    57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523]
    6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525]
    net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that
    might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks
    held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted
    6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536](CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved: l2tp: pass correct message length to
    ip6_append_data l2tp_ip6_sendmsg needs to avoid accounting for the transport header twice when splicing
    more data into an already partially-occupied skbuff. To manage this, we check whether the skbuff contains
    data using skb_queue_empty when deciding how much data to append using ip6_append_data. However, the code
    which performed the calculation was incorrect: ulen = len + skb_queue_empty(sk-sk_write_queue) ?
    transhdrlen : 0; ...due to C operator precedence, this ends up setting ulen to transhdrlen for messages
    with a non-zero length, which results in corrupted packets on the wire. Add parentheses to correct the
    calculation in line with the original intent.(CVE-2024-26752)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: use the backlog
    for mirred ingress The test Davide added in commit ca22da2fbd69 ('act_mirred: use the backlog for nested
    calls to mirred ingress') hangs our testing VMs every 10 or so runs, with the familiar tcp_v4_rcv -
    tcp_v4_rcv deadlock reported by lockdep. The problem as previously described by Davide (see Link) is that
    if we reverse flow of traffic with the redirect (egress - ingress) we may reach the same socket which
    generated the packet. And we may still be holding its socket lock. The common solution to such deadlocks
    is to put the packet in the Rx backlog, rather than run the Rx path inline. Do that for all egress -
    ingress reversals, not just once we started to nest mirred calls. In the past there was a concern that the
    backlog indirection will lead to loss of error reporting / less accurate stats. But the current workaround
    does not seem to address the issue.(CVE-2024-26740)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srp: Do not call scsi_done() from
    srp_abort() After scmd_eh_abort_handler() has called the SCSI LLD eh_abort_handler callback, it performs
    one of the following actions: * Call scsi_queue_insert(). * Call scsi_finish_command(). * Call
    scsi_eh_scmd_add(). Hence, SCSI abort handlers must not call scsi_done(). Otherwise all the above actions
    would trigger a use-after-free. Hence remove the scsi_done() call from srp_abort(). Keep the
    srp_free_req() call before returning SUCCESS because we may not see the command again if SUCCESS is
    returned.(CVE-2023-52515)

    In the Linux kernel, the following vulnerability has been resolved: hwrng: core - Fix page fault dead lock
    on mmap-ed hwrng There is a dead-lock in the hwrng device read path. This triggers when the user reads
    from /dev/hwrng into memory also mmap-ed from /dev/hwrng. The resulting page fault triggers a recursive
    read which then dead-locks. Fix this by using a stack buffer when calling copy_to_user.(CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved: KVM: s390: fix setting of fpc register
    kvm_arch_vcpu_ioctl_set_fpu() allows to set the floating point control (fpc) register of a guest cpu. The
    new value is tested for validity by temporarily loading it into the fpc register. This may lead to
    corruption of the fpc register of the host process: if an interrupt happens while the value is temporarily
    loaded into the fpc register, and within interrupt context floating point or vector registers are used,
    the current fp/vx registers are saved with save_fpu_regs() assuming they belong to user space and will be
    loaded into fp/vx registers when returning to user space. test_fp_ctl() restores the original user space /
    host process fpc register value, however it will be discarded, when returning to user space. In result the
    host process will incorrectly continue to run with the value that was supposed to be used for a guest cpu.
    Fix this by simply removing the test. There is another test right before the SIE context is entered which
    will handles invalid values. This results in a change of behaviour: invalid values will now be accepted
    instead of that the ioctl fails with -EINVAL. This seems to be acceptable, given that this interface is
    most likely not used anymore, and this is in addition the same behaviour implemented with the memory
    mapped interface (replace invalid values with zero) - see sync_regs() in kvm-s390.c.(CVE-2023-52597)

    In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

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

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT.We recommend upgrading past commit
    f342de4e2f33e0e39165d8639387aa6c19dff660.(CVE-2024-1086)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: GTDT: Don't corrupt interrupt
    mappings on watchdow probe failure When failing the driver probe because of invalid firmware properties,
    the GTDT driver unmaps the interrupt that it mapped earlier. However, it never checks whether the mapping
    of the interrupt actially succeeded. Even more, should the firmware report an illegal interrupt number
    that overlaps with the GIC SGI range, this can result in an IPI being unmapped, and subsequent fireworks
    (as reported by Dann Frazier). Rework the driver to have a slightly saner behaviour and actually check
    whether the interrupt has been mapped before unmapping things.(CVE-2021-46953)

    In the Linux kernel, the following vulnerability has been resolved: drivers/amd/pm: fix a use-after-free
    in kv_parse_power_table When ps allocated by kzalloc equals to NULL, kv_parse_power_table frees adev-
    pm.dpm.ps that allocated before. However, after the control flow goes through the following call
    chains: kv_parse_power_table |- kv_dpm_init |- kv_dpm_sw_init |- kv_dpm_fini The adev-
    pm.dpm.ps is used in the for loop of kv_dpm_fini after its first free in kv_parse_power_table and
    causes a use-after-free bug.(CVE-2023-52469)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Destroy I/O bus devices on
    unregister failure _after_ sync'ing SRCU If allocating a new instance of an I/O bus fails when
    unregistering a device, wait to destroy the device until after all readers are guaranteed to see the new
    null bus. Destroying devices before the bus is nullified could lead to use-after-free since readers expect
    the devices on their reference of the bus to remain valid.(CVE-2021-47061)

    In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-its: Avoid potential
    UAF in LPI translation cache There is a potential UAF scenario in the case of an LPI translation cache hit
    racing with an operation that invalidates the cache, such as a DISCARD ITS command. The root of the
    problem is that vgic_its_check_cache() does not elevate the refcount on the vgic_irq before dropping the
    lock that serializes refcount changes. Have vgic_its_check_cache() raise the refcount on the returned
    vgic_irq and add the corresponding decrement after queueing the interrupt.(CVE-2024-26598)

    In the Linux kernel, the following vulnerability has been resolved: i2c: validate user data in compat
    ioctl Wrong user data may cause warning in i2c_transfer(), ex: zero msgs. Userspace should not be able to
    trigger warnings, so this patch adds validation checks for user data in compact ioctl to prevent reported
    warnings(CVE-2021-46934)

    In the Linux kernel, the following vulnerability has been resolved: parisc: Clear stale IIR value on
    instruction access rights trap When a trap 7 (Instruction access rights) occurs, this means the CPU
    couldn't execute an instruction due to missing execute permissions on the memory region. In this case it
    seems the CPU didn't even fetched the instruction from memory and thus did not store it in the cr19 (IIR)
    register before calling the trap handler. So, the trap handler will find some random old stale value in
    cr19. This patch simply overwrites the stale IIR value with a constant magic 'bad food' value
    (0xbaadf00d), in the hope people don't start to try to understand the various random IIR values in trap 7
    dumps.(CVE-2021-46928)

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

    In the Linux kernel, the following vulnerability has been resolved: usb: hub: Guard against accesses to
    uninitialized BOS descriptors Many functions in drivers/usb/core/hub.c and drivers/usb/core/hub.h access
    fields inside udev-bos without checking if it was allocated and initialized. If
    usb_get_bos_descriptor() fails for whatever reason, udev-bos will be NULL and those accesses will
    result in a crash: BUG: kernel NULL pointer dereference, address: 0000000000000018 PGD 0 P4D
    0(CVE-2023-52477)

    In the Linux kernel, the following vulnerability has been resolved: EDAC/thunderx: Fix possible out-of-
    bounds string access Enabling -Wstringop-overflow globally exposes a warning for a common bug in the usage
    of strncat(): drivers/edac/thunderx_edac.c: In function 'thunderx_ocx_com_threaded_isr':
    drivers/edac/thunderx_edac.c:1136:17: error: 'strncat' specified bound 1024 equals destination size
    [-Werror=stringop-overflow=] 1136 | strncat(msg, other, OCX_MESSAGE_SIZE); |
    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ... 1145 | strncat(msg, other, OCX_MESSAGE_SIZE); ... 1150 |
    strncat(msg, other, OCX_MESSAGE_SIZE); ... Apparently the author of this driver expected strncat() to
    behave the way that strlcat() does, which uses the size of the destination buffer as its third argument
    rather than the length of the source buffer. The result is that there is no check on the size of the
    allocated buffer. Change it to strlcat(). [ bp: Trim compiler output, fixup commit message.
    ](CVE-2023-52464)

    In the Linux kernel, the following vulnerability has been resolved: cifs: Return correct error code from
    smb2_get_enc_key Avoid a warning if the error percolates back up: [440700.376476] CIFS VFS:
    \\otters.example.com crypt_message: Could not get encryption key [440700.386947] ------------[ cut here
    ]------------ [440700.386948] err = 1 [440700.386977] WARNING: CPU: 11 PID: 2733 at /build/linux-
    hwe-5.4-p6lk6L/linux-hwe-5.4-5.4.0/lib/errseq.c:74 errseq_set+0x5c/0x70 ... [440700.397304] CPU: 11 PID:
    2733 Comm: tar Tainted: G OE 5.4.0-70-generic #78~18.04.1-Ubuntu ... [440700.397334] Call Trace:
    [440700.397346] __filemap_set_wb_err+0x1a/0x70 [440700.397419] cifs_writepages+0x9c7/0xb30 [cifs]
    [440700.397426] do_writepages+0x4b/0xe0 [440700.397444] __filemap_fdatawrite_range+0xcb/0x100
    [440700.397455] filemap_write_and_wait+0x42/0xa0 [440700.397486] cifs_setattr+0x68b/0xf30 [cifs]
    [440700.397493] notify_change+0x358/0x4a0 [440700.397500] utimes_common+0xe9/0x1c0 [440700.397510]
    do_utimes+0xc5/0x150 [440700.397520] __x64_sys_utimensat+0x88/0xd0(CVE-2021-46960)

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

    In the Linux kernel, the following vulnerability has been resolved: ceph: fix deadlock or deadcode of
    misusing dget() The lock order is incorrect between denty and its parent, we should always make sure that
    the parent get the lock first. But since this deadcode is never used and the parent dir will always be set
    from the callers, let's just remove it.(CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved: ARM: 9064/1: hw_breakpoint: Do not
    directly check the event's overflow_handler hook The commit 1879445dfa7b ('perf/core: Set event's default
    ::overflow_handler()') set a default event-overflow_handler in perf_event_alloc(), and replace the
    check event-overflow_handler with is_default_overflow_handler(), but one is missing. Currently, the bp-
    overflow_handler can not be NULL. As a result, enable_single_step() is always not
    invoked.(CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: locking/qrwlock: Fix ordering in
    queued_write_lock_slowpath() While this code is executed with the wait_lock held, a reader can acquire the
    lock without holding wait_lock. The writer side loops checking the value with the
    atomic_cond_read_acquire(), but only truly acquires the lock when the compare-and-exchange is completed
    successfully which isnt ordered. This exposes the window between the acquire and the cmpxchg to an
    A-B-A problem which allows reads following the lock acquisition to observe values speculatively before the
    write lock is truly acquired. We've seen a problem in epoll where the reader does a xchg while holding the
    read lock, but the writer can see a value change out from under it. Writer | Reader
    -------------------------------------------------------------------------------- ep_scan_ready_list() | |-
    write_lock_irq() | |- queued_write_lock_slowpath() | |- atomic_cond_read_acquire() | |
    read_lock_irqsave(ep-lock, flags); -- (observes value before unlock) | chain_epi_lockless() | |
    epi-next = xchg(ep-ovflist, epi); | | read_unlock_irqrestore(ep-lock, flags); | | |
    atomic_cmpxchg_relaxed() | |-- READ_ONCE(ep-ovflist); | A core can order the read of the ovflist ahead
    of the atomic_cmpxchg_relaxed(). Switching the cmpxchg to use acquire semantics addresses this issue at
    which point the atomic_cond_read can be switched to use relaxed semantics.(CVE-2021-46921)

    The IPv6 implementation in the Linux kernel before 6.3 has a net/ipv6/route.c max_size threshold that can
    be consumed easily, e.g., leading to a denial of service (network is unreachable errors) when IPv6 packets
    are sent in a loop via a raw socket.(CVE-2023-52340)

    In the Linux kernel, the following vulnerability has been resolved: pstore/ram: Fix crash when setting
    number of cpus to an odd number When the number of cpu cores is adjusted to 7 or other odd numbers, the
    zone size will become an odd number. The address of the zone will become: addr of zone0 = BASE addr of
    zone1 = BASE + zone_size addr of zone2 = BASE + zone_size*2 ... The address of zone1/3/5/7 will be mapped
    to non-alignment va. Eventually crashes will occur when accessing these va. So, use ALIGN_DOWN() to make
    sure the zone size is even to avoid this bug.(CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved: NFS: fs_context: validate UDP retrans
    to prevent shift out-of-bounds Fix shift out-of-bounds in xprt_calc_majortimeo(). This is caused by a
    garbage timeout (retrans) mount option being passed to nfs mount, in this case from syzkaller. If the
    protocol is XPRT_TRANSPORT_UDP, then 'retrans' is a shift value for a 64-bit long integer, so 'retrans'
    cannot be = 64. If it is = 64, fail the mount and return an error.(CVE-2021-46952)

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

    In the Linux kernel, the following vulnerability has been resolved: net: fix possible store tearing in
    neigh_periodic_work() While looking at a related syzbot report involving neigh_periodic_work(), I found
    that I forgot to add an annotation when deleting an RCU protected item from a list. Readers use
    rcu_deference(*np), we need to use either rcu_assign_pointer() or WRITE_ONCE() on writer side to prevent
    store tearing. I use rcu_assign_pointer() to have lockdep support, this was the choice made in
    neigh_flush_dev().(CVE-2023-52522)

    In the Linux kernel, the following vulnerability has been resolved: net:emac/emac-mac: Fix a use after
    free in emac_mac_tx_buf_send In emac_mac_tx_buf_send, it calls emac_tx_fill_tpd(..,skb,..). If some error
    happens in emac_tx_fill_tpd(), the skb will be freed via dev_kfree_skb(skb) in error branch of
    emac_tx_fill_tpd(). But the freed skb is still used via skb-len by netdev_sent_queue(,skb-len). As i
    observed that emac_tx_fill_tpd() haven't modified the value of skb-len, thus my patch assigns skb-
    len to 'len' before the possible free and use 'len' instead of skb-len later.(CVE-2021-47013)

    In the Linux kernel, the following vulnerability has been resolved: bnxt_en: Fix RX consumer index logic
    in the error path. In bnxt_rx_pkt(), the RX buffers are expected to complete in order. If the RX consumer
    index indicates an out of order buffer completion, it means we are hitting a hardware bug and the driver
    will abort all remaining RX packets and reset the RX ring. The RX consumer index that we pass to
    bnxt_discard_rx() is not correct. We should be passing the current index (tmp_raw_cons) instead of the old
    index (raw_cons). This bug can cause us to be at the wrong index when trying to abort the next RX
    packet.(CVE-2021-47015)

    In the Linux kernel, the following vulnerability has been resolved: net: Only allow init netns to set
    default tcp cong to a restricted algo tcp_set_default_congestion_control() is netns-safe in that it writes
    to net-ipv4.tcp_congestion_control, but it also sets ca-flags |= TCP_CONG_NON_RESTRICTED which is
    not namespaced. This has the unintended side-effect of changing the global
    net.ipv4.tcp_allowed_congestion_control sysctl, despite the fact that it is read-only: 97684f0970f6 ('net:
    Make tcp_allowed_congestion_control readonly in non-init netns') Resolve this netns 'leak' by only
    allowing the init netns to set the default algorithm to one that is restricted. This restriction could be
    removed if tcp_allowed_congestion_control were namespace-ified in the future.(CVE-2021-47010)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: smsc75xx: Fix uninit-value
    access in __smsc75xx_read_reg syzbot reported the following uninit-value access issue: BUG: KMSAN: uninit-
    value in smsc75xx_wait_ready(CVE-2023-52528)

    A race condition was found in the Linux kernel's scsi device driver in lpfc_unregister_fcf_rescan()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24855)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid online resizing failures
    due to oversized flex bg When we online resize an ext4 filesystem with a oversized flexbg_size, mkfs.ext4
    -F -G 67108864 $dev -b 4096 100M mount $dev $dir resize2fs $dev 16G the following WARN_ON is triggered:
    WARNING: CPU: 0 PID: 427 at mm/page_alloc.c:4402 __alloc_pages+0x411/0x550 Modules linked in: sg(E) CPU: 0
    PID: 427 Comm: resize2fs Tainted: G E 6.6.0-rc5+ #314 RIP: 0010:__alloc_pages+0x411/0x550 Call Trace:
    TASK __kmalloc_large_node+0xa2/0x200 __kmalloc+0x16e/0x290 ext4_resize_fs+0x481/0xd80
    __ext4_ioctl+0x1616/0x1d90 ext4_ioctl+0x12/0x20 __x64_sys_ioctl+0xf0/0x150 do_syscall_64+0x3b/0x90
    =====This is because flexbg_size is too large and the size of the new_group_data array to be allocated
    exceeds MAX_ORDER. Currently, the minimum value of MAX_ORDER is 8, the minimum value of PAGE_SIZE is 4096,
    the corresponding maximum number of groups that can be allocated is: (PAGE_SIZE  MAX_ORDER) /
    sizeof(struct ext4_new_group_data)  21845 And the value that is down-aligned to the power of 2 is
    16384. Therefore, this value is defined as MAX_RESIZE_BG, and the number of groups added each time does
    not exceed this value during resizing, and is added multiple times to complete the online resizing. The
    difference is that the metadata in a flex_bg may be more dispersed.(CVE-2023-52622)

    In the Linux kernel, the following vulnerability has been resolved: nvme-loop: fix memory leak in
    nvme_loop_create_ctrl() When creating loop ctrl in nvme_loop_create_ctrl(), if nvme_init_ctrl() fails, the
    loop ctrl should be freed before jumping to the 'out' label.(CVE-2021-47074)

    In the Linux kernel, the following vulnerability has been resolved: userfaultfd: release page in error
    path to avoid BUG_ON Consider the following sequence of events: 1. Userspace issues a UFFD ioctl, which
    ends up calling into shmem_mfill_atomic_pte(). We successfully account the blocks, we shmem_alloc_page(),
    but then the copy_from_user() fails. We return -ENOENT. We don't release the page we allocated. 2. Our
    caller detects this error code, tries the copy_from_user() after dropping the mmap_lock, and retries,
    calling back into shmem_mfill_atomic_pte(). 3. Meanwhile, let's say another process filled up the tmpfs
    being used. 4. So shmem_mfill_atomic_pte() fails to account blocks this time, and immediately returns -
    without releasing the page. This triggers a BUG_ON in our caller, which asserts that the page should
    always be consumed, unless -ENOENT is returned. To fix this, detect if we have such a 'dangling' page when
    accounting fails, and if so, release it before returning.(CVE-2021-46988)

    A use-after-free flaw was found in the __ext4_remount in fs/ext4/super.c in ext4 in the Linux kernel. This
    flaw allows a local user to cause an information leak problem while freeing the old quota file names
    before a potential failure, leading to a use-after-free.(CVE-2024-0775)

    Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0.(CVE-2021-33631)

    In the Linux kernel, the following vulnerability has been resolved:NFS: Fix an Oopsable condition in
    __nfs_pageio_add_request().Ensure that nfs_pageio_error_cleanup() resets the mirror array contents,so that
    the structure reflects the fact that it is now empty.Also change the test in nfs_pageio_do_add_request()
    to be more robust by checking whether or not the list is empty rather than relying on the value of
    pg_count.(CVE-2021-47167)

    In the Linux kernel, the following vulnerability has been resolved:crypto: scomp - fix req-dst buffer
    overflow.The req-dst buffer size should be checked before copying from the scomp_scratch-dst to
    avoid req-dst buffer overflow problem.(CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved: sched/membarrier: reduce the ability
    to hammer on sys_membarrier On some systems, sys_membarrier can be very expensive, causing overall
    slowdowns for everything. So put a lock on the path in order to serialize the accesses to prevent the
    ability for this to be called at too high of a frequency and saturate the machine.(CVE-2024-26602)

    Integer Overflow or Wraparound vulnerability in Linux Linux kernel kernel on Linux, x86, ARM (md, raid,
    raid5 modules) allows Forced Integer Overflow.(CVE-2024-23307)

    In the Linux kernel, the following vulnerability has been resolved: dm rq: fix double free of
    blk_mq_tag_set in dev remove after table load fails When loading a device-mapper table for a request-based
    mapped device, and the allocation/initialization of the blk_mq_tag_set for the device fails, a following
    device remove will cause a double free. E.g. (dmesg): device-mapper: core: Cannot initialize queue for
    request-based dm-mq mapped device device-mapper: ioctl: unable to set up device queue for new table.
    Unable to handle kernel pointer dereference in virtual kernel address space Failing address:
    0305e098835de000 TEID: 0305e098835de803 Fault in home space mode while using kernel ASCE.
    AS:000000025efe0007 R3:0000000000000024 Oops: 0038 ilc:3 [#1] SMP Modules linked in: ... lots of modules
    ... Supported: Yes, External CPU: 0 PID: 7348 Comm: multipathd Kdump: loaded Tainted: G W X
    5.3.18-53-default #1 SLE15-SP3 Hardware name: IBM 8561 T01 7I2 (LPAR) Krnl PSW : 0704e00180000000
    000000025e368eca (kfree+0x42/0x330) R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:2 PM:0 RI:0 EA:3 Krnl
    GPRS: 000000000000004a 000000025efe5230 c1773200d779968d 0000000000000000 000000025e520270
    000000025e8d1b40 0000000000000003 00000007aae10000 000000025e5202a2 0000000000000001 c1773200d779968d
    0305e098835de640 00000007a8170000 000003ff80138650 000000025e5202a2 000003e00396faa8 Krnl Code:
    000000025e368eb8: c4180041e100 lgrl %r1,25eba50b8 000000025e368ebe: ecba06b93a55 risbg %r11,%r10,6,185,58
    #000000025e368ec4: e3b010000008 ag %r11,0(%r1) 000000025e368eca: e310b0080004 lg %r1,8(%r11)
    000000025e368ed0: a7110001 tmll %r1,1 000000025e368ed4: a7740129 brc 7,25e369126 000000025e368ed8:
    e320b0080004 lg %r2,8(%r11) 000000025e368ede: b904001b lgr %r1,%r11(CVE-2021-46938)

    In the Linux kernel, the following vulnerability has been resolved: NFS: Don't corrupt the value of
    pg_bytes_written in nfs_do_recoalesce() The value of mirror-pg_bytes_written should only be updated
    after a successful attempt to flush out the requests on the list.(CVE-2021-47166)

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

    A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality.(CVE-2024-0607)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted.(CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved: i2c: Fix a potential use after free
    Free the adap structure only after we are done using it. This patch just moves the put_device() down a bit
    to avoid the use after free. [wsa: added comment to the code, added Fixes tag](CVE-2019-25162)

    In the Linux kernel, the following vulnerability has been resolved: drm: bridge/panel: Cleanup connector
    on bridge detach If we don't call drm_connector_cleanup() manually in panel_bridge_detach(), the connector
    will be cleaned up with the other DRM objects in the call to drm_mode_config_cleanup(). However, since our
    drm_connector is devm-allocated, by the time drm_mode_config_cleanup() will be called, our connector will
    be long gone. Therefore, the connector must be cleaned up when the bridge is detached to avoid use-after-
    free conditions. v2: Cleanup connector only if it was created v3: Add FIXME v4: (Use connector-dev)
    directly in if() block(CVE-2021-47063)

    In the Linux kernel, the following vulnerability has been resolved: bus: qcom: Put child node before
    return Put child node before return to fix potential reference count leak. Generally, the reference count
    of child is incremented and decremented automatically in the macro for_each_available_child_of_node() and
    should be decremented manually if the loop is broken in loop body.(CVE-2021-47054)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in
    skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a
    forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily :
    mss = mss * partial_segs; 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final
    result. Make sure to limit segmentation so that the new mss value is smaller than
    GSO_BY_FRAGS.(CVE-2023-52435)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Return CQE error if invalid
    lkey was supplied RXE is missing update of WQE status in LOCAL_WRITE failures. This caused the following
    kernel panic if someone sent an atomic operation with an explicitly wrong lkey.(CVE-2021-47076)

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

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_limit: avoid possible
    divide error in nft_limit_init div_u64() divides u64 by u32. nft_limit_init() wants to divide u64 by u64,
    use the appropriate math function (div64_u64) divide error: 0000 [#1] PREEMPT SMP KASAN CPU: 1 PID: 8390
    Comm: syz-executor188 Not tainted 5.12.0-rc4-syzkaller(CVE-2021-46915)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: sr: fix possible use-after-free
    and null-ptr-deref The pernet operations structure for the subsystem must be registered before registering
    the generic netlink family.(CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow
    anonymous set with timeout flag Anonymous sets are never used with timeout from userspace, reject this.
    Exception to this rule is NFT_SET_EVAL to ensure legacy meters still work.(CVE-2024-26642)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fix a use-after-free looks
    like we forget to set ttm-sg to NULL.(CVE-2021-47142)

    In the Linux kernel, the following vulnerability has been resolved: tcp: add sanity checks to rx zerocopy
    TCP rx zerocopy intent is to map pages initially allocated from NIC drivers, not pages owned by a fs. This
    patch adds to can_map_frag() these additional checks: - Page must not be a compound one. - page-mapping
    must be NULL. This fixes the panic reported by ZhangPeng. syzbot was able to loopback packets built with
    sendfile(), mapping pages owned by an ext4 file to TCP rx zerocopy. r3 = socket$inet_tcp(0x2, 0x1, 0x0)
    mmap((0x7f0000ff9000/0x4000)=nil, 0x4000, 0x0, 0x12, r3, 0x0) r4 = socket$inet_tcp(0x2, 0x1, 0x0)
    bind$inet(r4, (0x7f0000000000)={0x2, 0x4e24, @multicast1}, 0x10) connect$inet(r4,
    (0x7f00000006c0)={0x2, 0x4e24, @empty}, 0x10) r5 = openat$dir(0xffffffffffffff9c,
    (0x7f00000000c0)='./file0\x00', 0x181e42, 0x0) fallocate(r5, 0x0, 0x0, 0x85b8) sendfile(r4, r5, 0x0,
    0x8ba0) getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE(r4, 0x6, 0x23,
    (0x7f00000001c0)={(0x7f0000ffb000/0x3000)=nil, 0x3000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
    (0x7f0000000440)=0x40) r6 = openat$dir(0xffffffffffffff9c, (0x7f00000000c0)='./file0\x00', 0x181e42,
    0x0)(CVE-2024-26640)

    In the Linux kernel, the following vulnerability has been resolved: USB: usbfs: Don't WARN about
    excessively large memory allocations Syzbot found that the kernel generates a WARNing if the user tries to
    submit a bulk transfer through usbfs with a buffer that is way too large. This isn't a bug in the kernel;
    it's merely an invalid request from the user and the usbfs code does handle it correctly. In theory the
    same thing can happen with async transfers, or with the packet descriptor table for isochronous transfers.
    To prevent the MM subsystem from complaining about these bad allocation requests, add the __GFP_NOWARN
    flag to the kmalloc calls for these buffers.(CVE-2021-47170)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: fix memory leak in
    smsc75xx_bind Syzbot reported memory leak in smsc75xx_bind(). The problem was is non-freed memory in case
    of errors after memory allocation.(CVE-2021-47171)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Ensure visibility when
    inserting an element into tracing_map Running the following two commands in parallel on a multi-processor
    AArch64 machine can sporadically produce an unexpected warning about duplicate histogram entries: $ while
    true; do echo hist:key=id.syscall:val=hitcount  \
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/trigger cat
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/hist sleep 0.001 done $ stress-ng --sysbadaddr
    $(nproc)(CVE-2024-26645)

    In the Linux kernel, the following vulnerability has been resolved: mld: fix panic in mld_newpack()
    mld_newpack() doesn't allow to allocate high order page, only order-0 allocation is allowed. If headroom
    size is too large, a kernel panic could occur in skb_put(). Test commands: ip netns del A ip netns del B
    ip netns add A ip netns add B ip link add veth0 type veth peer name veth1 ip link set veth0 netns A ip
    link set veth1 netns B ip netns exec A ip link set lo up ip netns exec A ip link set veth0 up ip netns
    exec A ip -6 a a 2001:db8:0::1/64 dev veth0 ip netns exec B ip link set lo up ip netns exec B ip link set
    veth1 up ip netns exec B ip -6 a a 2001:db8:0::2/64 dev veth1 for i in {1..99} do let A=$i-1 ip netns exec
    A ip link add ip6gre$i type ip6gre \ local 2001:db8:$A::1 remote 2001:db8:$A::2 encaplimit 100 ip netns
    exec A ip -6 a a 2001:db8:$i::1/64 dev ip6gre$i ip netns exec A ip link set ip6gre$i up ip netns exec B ip
    link add ip6gre$i type ip6gre \ local 2001:db8:$A::2 remote 2001:db8:$A::1 encaplimit 100 ip netns exec B
    ip -6 a a 2001:db8:$i::2/64 dev ip6gre$i ip netns exec B ip link set ip6gre$i up done Splat looks like:
    kernel BUG at net/core/skbuff.c:110! invalid opcode: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI CPU: 0 PID: 7
    Comm: kworker/0:1 Not tainted 5.12.0+ #891 Workqueue: ipv6_addrconf addrconf_dad_work RIP:
    0010:skb_panic+0x15d/0x15f Code: 92 fe 4c 8b 4c 24 10 53 8b 4d 70 45 89 e0 48 c7 c7 00 ae 79 83 41 57 41
    56 41 55 48 8b 54 24 a6 26 f9 ff 0f 0b 48 8b 6c 24 20 89 34 24 e8 4a 4e 92 fe 8b 34 24 48 c7 c1 20
    RSP: 0018:ffff88810091f820 EFLAGS: 00010282 RAX: 0000000000000089 RBX: ffff8881086e9000 RCX:
    0000000000000000 RDX: 0000000000000089 RSI: 0000000000000008 RDI: ffffed1020123efb RBP: ffff888005f6eac0
    R08: ffffed1022fc0031 R09: ffffed1022fc0031 R10: ffff888117e00187 R11: ffffed1022fc0030 R12:
    0000000000000028 R13: ffff888008284eb0 R14: 0000000000000ed8 R15: 0000000000000ec0 FS:
    0000000000000000(0000) GS:ffff888117c00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007f8b801c5640 CR3: 0000000033c2c006 CR4: 00000000003706f0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: ? ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600 ?
    ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600 skb_put.cold.104+0x22/0x22
    ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600 ? rcu_read_lock_sched_held+0x91/0xc0 mld_newpack+0x398/0x8f0 ?
    ip6_mc_hdr.isra.26.constprop.46+0x600/0x600 ? lock_contended+0xc40/0xc40 add_grhead.isra.33+0x280/0x380
    add_grec+0x5ca/0xff0 ? mld_sendpack+0xf40/0xf40 ? lock_downgrade+0x690/0x690
    mld_send_initial_cr.part.34+0xb9/0x180 ipv6_mc_dad_complete+0x15d/0x1b0 addrconf_dad_completed+0x8d2/0xbb0
    ? lock_downgrade+0x690/0x690 ? addrconf_rs_timer+0x660/0x660 ? addrconf_dad_work+0x73c/0x10e0
    addrconf_dad_work+0x73c/0x10e0 Allowing high order page allocation could fix this problem.(CVE-2021-47146)

    In the Linux kernel, the following vulnerability has been resolved: llc: Drop support for ETH_P_TR_802_2.
    syzbot reported an uninit-value bug below. [0] llc supports ETH_P_802_2 (0x0004) and used to support
    ETH_P_TR_802_2 (0x0011), and syzbot abused the latter to trigger the bug. write$tun(r0,
    (0x7f0000000040)={@val={0x0, 0x11}, @val, @mpls={[], @llc={@snap={0xaa, 0x1, ')', ''90e5dd''}}}}, 0x16)
    llc_conn_handler() initialises local variables {saddr,daddr}.mac based on skb in
    llc_pdu_decode_sa()/llc_pdu_decode_da() and passes them to __llc_lookup(). However, the initialisation is
    done only when skb-protocol is htons(ETH_P_802_2), otherwise, __llc_lookup_established() and
    __llc_lookup_listener() will read garbage. The missing initialisation existed prior to commit 211ed865108e
    (''net: delete all instances of special processing for token ring''). It removed the part to kick out the
    token ring stuff but forgot to close the door allowing ETH_P_TR_802_2 packets to sneak into llc_rcv().
    Let's remove llc_tr_packet_type and complete the deprecation.(CVE-2024-26635)

    In the Linux kernel, the following vulnerability has been resolved: inet: read sk-sk_family once in
    inet_recv_error() inet_recv_error() is called without holding the socket lock. IPv6 socket could mutate to
    IPv4 with IPV6_ADDRFORM socket option and trigger a KCSAN warning.(CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved: asix: fix uninit-value in
    asix_mdio_read() asix_read_cmd() may read less than sizeof(smsr) bytes and in this case smsr will be
    uninitialized.(CVE-2021-47101)

    In the Linux kernel, the following vulnerability has been resolved: mac80211: fix locking in
    ieee80211_start_ap error path We need to hold the local-mtx to release the channel context, as even
    encoded by the lockdep_assert_held() there.(CVE-2021-47091)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: fix NEXTHDR_FRAGMENT
    handling in ip6_tnl_parse_tlv_enc_lim() syzbot pointed out [1] that NEXTHDR_FRAGMENT handling is broken.
    Reading frag_off can only be done if we pulled enough bytes to skb-head. Currently we might access
    garbage.(CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_find_by_goal() Places the logic for checking if the group's block bitmap is
    corrupt under the protection of the group lock to avoid allocating blocks from the group with a corrupted
    block bitmap.(CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: fix race condition on
    enabling fast-xmit fast-xmit must only be enabled after the sta has been uploaded to the driver, otherwise
    it could end up passing the not-yet-uploaded sta via drv_tx calls to the driver, leading to potential
    crashes because of uninitialized drv_priv data. Add a missing sta-uploaded check and re-check fast xmit
    after inserting a sta.(CVE-2024-26779)

    In the Linux kernel, the following vulnerability has been resolved:NFS: fix an incorrect limit in
    filelayout_decode_layout().The ''sizeof(struct nfs_fh)'' is two bytes too large and could lead to memory
    corruption.  It should be NFS_MAXFHSIZE because that's the sizethe -data[] buffer. I reversed the size
    of the arguments to put the variable on the left.(CVE-2021-47168)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: prevent perpetual
    headroom growth syzkaller triggered following kasan splat: BUG: KASAN: use-after-free in
    __skb_flow_dissect+0x19d1/0x7a50(CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved: mm/swap: fix race when skipping
    swapcache When skipping swapcache for SWP_SYNCHRONOUS_IO, if two or more threads swapin the same entry at
    the same time, they get different pages (A, B). Before one thread (T0) finishes the swapin and installs
    page (A) to the PTE, another thread (T1) could finish swapin of page (B), swap_free the entry, then swap
    out the possibly modified page reusing the same entry. It breaks the pte_same check in (T0) because PTE
    value is unchanged, causing ABA problem. Thread (T0) will install a stalled page (A) into the PTE and
    cause data corruption.(CVE-2024-26759)

    In the Linux kernel, the following vulnerability has been resolved: mm/writeback: fix possible divide-by-
    zero in wb_dirty_limits(), again (struct dirty_throttle_control *)-thresh is an unsigned long, but is
    passed as the u32 divisor argument to div_u64(). On architectures where unsigned long is 64 bytes, the
    argument will be implicitly truncated. Use div64_u64() instead of div_u64() so that the value used in the
    ''is this a safe division'' check is the same as the divisor. Also, remove redundant cast of the numerator
    to u64, as that should happen implicitly. This would be difficult to exploit in memcg domain, given the
    ratio-based arithmetic domain_drity_limits() uses, but is much easier in global writeback domain with a
    BDI_CAP_STRICTLIMIT-backing device, using e.g. vm.dirty_bytes=(132)*PAGE_SIZE so that dtc-thresh
    == (132)(CVE-2024-26720)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_try_best_found() Determine if the group block bitmap is corrupted before using
    ac_b_ex in ext4_mb_try_best_found() to avoid allocating blocks from a group with a corrupted block bitmap
    in the following concurrency and making the situation worse. ext4_mb_regular_allocator ext4_lock_group(sb,
    group) ext4_mb_good_group // check if the group bbitmap is corrupted ext4_mb_complex_scan_group // Scan
    group gets ac_b_ex but doesn't use it ext4_unlock_group(sb, group) ext4_mark_group_bitmap_corrupted(group)
    // The block bitmap was corrupted during // the group unlock gap. ext4_mb_try_best_found
    ext4_lock_group(ac-ac_sb, group) ext4_mb_use_best_found mb_mark_used // Allocating blocks in block
    bitmap corrupted group(CVE-2024-26773)

    In the Linux kernel, the following vulnerability has been resolved: dm-crypt: don't modify the data when
    using authenticated encryption It was said that authenticated encryption could produce invalid tag when
    the data that is being encrypted is modified [1]. So, fix this problem by copying the data into the clone
    bio first and then encrypt them inside the clone bio. This may reduce performance, but it is needed to
    prevent the user from corrupting the device by writing data with O_DIRECT and modifying them at the same
    time.(CVE-2024-26763)

    In the Linux kernel, the following vulnerability has been resolved: netlink: Fix kernel-infoleak-after-
    free in __skb_datagram_iter syzbot reported the following uninit-value access issue [1]:
    netlink_to_full_skb() creates a new `skb` and puts the `skb-data` passed as a 1st arg of
    netlink_to_full_skb() onto new `skb`. The data size is specified as `len` and passed to skb_put_data().
    This `len` is based on `skb-end` that is not data offset but buffer offset. The `skb-end` contains
    data and tailroom. Since the tailroom is not initialized when the new `skb` created, KMSAN detects
    uninitialized memory area when copying the data. This patch resolved this issue by correct the len from
    `skb-end` to `skb-len`, which is the actual data offset.(CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved: net/tls: Fix use-after-free after the
    TLS device goes down and up When a netdev with active TLS offload goes down, tls_device_down is called to
    stop the offload and tear down the TLS context. However, the socket stays alive, and it still points to
    the TLS context, which is now deallocated. If a netdev goes up, while the connection is still active, and
    the data flow resumes after a number of TCP retransmissions, it will lead to a use-after-free of the TLS
    context. This commit addresses this bug by keeping the context alive until its normal destruction, and
    implements the necessary fallbacks, so that the connection can resume in software (non-offloaded) kTLS
    mode. On the TX side tls_sw_fallback is used to encrypt all packets. The RX side already has all the
    necessary fallbacks, because receiving non-decrypted packets is supported. The thing needed on the RX side
    is to block resync requests, which are normally produced after receiving non-decrypted packets. The
    necessary synchronization is implemented for a graceful teardown: first the fallbacks are deployed, then
    the driver resources are released (it used to be possible to have a tls_dev_resync after tls_dev_del). A
    new flag called TLS_RX_DEV_DEGRADED is added to indicate the fallback mode. It's used to skip the RX
    resync logic completely, as it becomes useless, and some objects may be released (for example,
    resync_async, which is allocated and freed by the driver).(CVE-2021-47131)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow timeout
    for anonymous sets Never used from userspace, disallow these parameters.(CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved: vt: fix memory overlapping when
    deleting chars in the buffer A memory overlapping copy occurs when deleting a long line. This memory
    overlapping copy can cause data corruption when scr_memcpyw is optimized to memcpy because memcpy does not
    ensure its behavior if the destination buffer overlaps with the source buffer. The line buffer is not
    always broken, because the memcpy utilizes the hardware acceleration, whose result is not deterministic.
    Fix this problem by using replacing the scr_memcpyw with scr_memmovew.(CVE-2022-48627)

    In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: fix potential key use-
    after-free When ieee80211_key_link() is called by ieee80211_gtk_rekey_add() but returns 0 due to KRACK
    protection (identical key reinstall), ieee80211_gtk_rekey_add() will still return a pointer into the key,
    in a potential use-after-free. This normally doesn't happen since it's only called by iwlwifi in case of
    WoWLAN rekey offload which has its own KRACK protection, but still better to fix, do that by returning an
    error code and converting that to success on the cfg80211 boundary only, leaving the error for bad callers
    of ieee80211_gtk_rekey_add().(CVE-2023-52530)

    In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev-stats fields. Handles updates to
    dev-stats.tx_dropped while we are at it.(CVE-2023-52578)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Clear all QP fields if
    creation failed rxe_qp_do_cleanup() relies on valid pointer values in QP for the properly created ones,
    but in case rxe_qp_from_init() failed it was filled with garbage and caused tot the following error.
    refcount_t: underflow; use-after-free.(CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved: Input: appletouch - initialize work
    before device registration Syzbot has reported warning in __flush_work(). This warning is caused by work-
    func == NULL, which means missing work initialization. This may happen, since input_dev-close()
    calls cancel_work_sync(dev-work), but dev-work initalization happens _after_
    input_register_device() call. So this patch moves dev-work initialization before registering input
    device(CVE-2021-46932)

    In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has
    a fence use-after-free.(CVE-2023-51042)

    An issue was discovered in drivers/input/input.c in the Linux kernel before 5.17.10. An attacker can cause
    a denial of service (panic) because input_set_capability mishandles the situation in which an event code
    falls outside of a bitmap.(CVE-2022-48619)

    In the Linux kernel, the following vulnerability has been resolved: vsock/virtio: free queued packets when
    closing socket As reported by syzbot [1], there is a memory leak while closing the socket. We partially
    solved this issue with commit ac03046ece2b (''vsock/virtio: free packets during the socket release''), but
    we forgot to drain the RX queue when the socket is definitely closed by the scheduled work. To avoid
    future issues, let's use the new virtio_transport_remove_sock() to drain the RX queue before removing the
    socket from the af_vsock lists calling vsock_remove_sock().(CVE-2021-47024)

    In the Linux kernel, the following vulnerability has been resolved: net: fix use-after-free in
    tw_timer_handler A real world panic issue was found as follow in Linux 5.4. BUG: unable to handle page
    fault for address: ffffde49a863de28 PGD 7e6fe62067 P4D 7e6fe62067 PUD 7e6fe63067 PMD f51e064067 PTE 0 RIP:
    0010:tw_timer_handler+0x20/0x40 Call Trace: IRQ call_timer_fn+0x2b/0x120
    run_timer_softirq+0x1ef/0x450 __do_softirq+0x10d/0x2b8 irq_exit+0xc7/0xd0
    smp_apic_timer_interrupt+0x68/0x120 apic_timer_interrupt+0xf/0x20 This issue was also reported since 2017
    in the thread [1], unfortunately, the issue was still can be reproduced after fixing DCCP. The
    ipv4_mib_exit_net is called before tcp_sk_exit_batch when a net namespace is destroyed since tcp_sk_ops is
    registered befrore ipv4_mib_ops, which means tcp_sk_ops is in the front of ipv4_mib_ops in the list of
    pernet_list. There will be a use-after-free on net-mib.net_statistics in tw_timer_handler after
    ipv4_mib_exit_net if there are some inflight time-wait timers. This bug is not introduced by commit
    f2bf415cfed7 (''mib: add net to NET_ADD_STATS_BH'') since the net_statistics is a global variable instead
    of dynamic allocation and freeing. Actually, commit 61a7e26028b9 (''mib: put net statistics on struct
    net'') introduces the bug since it put net statistics on struct net and free it when net namespace is
    destroyed. Moving init_ipv4_mibs() to the front of tcp_init() to fix this bug and replace pr_crit() with
    panic() since continuing is meaningless when init_ipv4_mibs() fails. [1]
    https://groups.google.com/g/syzkaller/c/p1tn-_Kc6l4/m/smuL_FMAAgAJ?pli=1(CVE-2021-46936)

    In the Linux kernel, the following vulnerability has been resolved: scsi: qedf: Add pointer checks in
    qedf_update_link_speed() The following trace was observed: [ 14.042059] Call Trace: [ 14.042061] IRQ
    [ 14.042068] qedf_link_update+0x144/0x1f0 [qedf] [ 14.042117] qed_link_update+0x5c/0x80 [qed] [ 14.042135]
    qed_mcp_handle_link_change+0x2d2/0x410 [qed] [ 14.042155] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042170] ?
    qed_set_ptt+0x70/0x80 [qed] [ 14.042186] ? qed_rd+0x13/0x40 [qed] [ 14.042205]
    qed_mcp_handle_events+0x437/0x690 [qed] [ 14.042221] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042239]
    qed_int_sp_dpc+0x3a6/0x3e0 [qed] [ 14.042245] tasklet_action_common.isra.14+0x5a/0x100 [ 14.042250]
    __do_softirq+0xe4/0x2f8 [ 14.042253] irq_exit+0xf7/0x100 [ 14.042255] do_IRQ+0x7f/0xd0 [ 14.042257]
    common_interrupt+0xf/0xf [ 14.042259] /IRQ API qedf_link_update() is getting called from QED but by
    that time shost_data is not initialised. This results in a NULL pointer dereference when we try to
    dereference shost_data while updating supported_speeds. Add a NULL pointer check before dereferencing
    shost_dat(CVE-2021-47077)

    In the Linux kernel, the following vulnerability has been resolved: scsi: lpfc: Fix list_add() corruption
    in lpfc_drain_txq() When parsing the txq list in lpfc_drain_txq(), the driver attempts to pass the
    requests to the adapter. If such an attempt fails, a local ''fail_msg'' string is set and a log message
    output. The job is then added to a completions list for cancellation. Processing of any further jobs from
    the txq list continues, but since ''fail_msg'' remains set, jobs are added to the completions list
    regardless of whether a wqe was passed to the adapter. If successfully added to txcmplq, jobs are added to
    both lists resulting in list corruption. Fix by clearing the fail_msg string after adding a job to the
    completions list. This stops the subsequent jobs from being added to the completions list unless they had
    an appropriate failure.(CVE-2021-47203)

    In the Linux kernel, the following vulnerability has been resolved: HID: logitech-hidpp: Fix kernel crash
    on receiver USB disconnect hidpp_connect_event() has *four* time-of-check vs time-of-use (TOCTOU) races
    when it races with itself. hidpp_connect_event() primarily runs from a workqueue but it also runs on
    probe() and if a ''device-connected'' packet is received by the hw when the thread running
    hidpp_connect_event() from probe() is waiting on the hw, then a second thread running
    hidpp_connect_event() will be started from the workqueue. This opens the following races (note the below
    code is simplified): 1. Retrieving + printing the protocol (harmless race): if (!hidpp-protocol_major)
    { hidpp_root_get_protocol_version() hidpp-protocol_major = response.rap.params[0]; } We can actually
    see this race hit in the dmesg in the abrt output attached to rhbz#2227968: [ 3064.624215] logitech-hidpp-
    device 0003:046D:4071.0049: HID++ 4.5 device connected. [ 3064.658184] logitech-hidpp-device
    0003:046D:4071.0049: HID++ 4.5 device connected. Testing with extra logging added has shown that after
    this the 2 threads take turn grabbing the hw access mutex (send_mutex) so they ping-pong through all the
    other TOCTOU cases managing to hit all of them: 2. Updating the name to the HIDPP name (harmless race): if
    (hidpp-name == hdev-name) { ... hidpp-name = new_name; } 3. Initializing the power_supply class
    for the battery (problematic!): hidpp_initialize_battery() { if (hidpp-battery.ps) return 0;
    probe_battery(); /* Blocks, threads take turns executing this */ hidpp-battery.desc.properties =
    devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL); hidpp-battery.ps =
    devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc, cfg); } 4. Creating
    delayed input_device (potentially problematic): if (hidpp-delayed_input) return; hidpp-delayed_input
    = hidpp_allocate_input(hdev); The really big problem here is 3. Hitting the race leads to the following
    sequence: hidpp-battery.desc.properties = devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL);
    hidpp-battery.ps = devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc,
    cfg); ... hidpp-battery.desc.properties = devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL);
    hidpp-battery.ps = devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc,
    cfg); So now we have registered 2 power supplies for the same battery, which looks a bit weird from
    userspace's pov but this is not even the really big problem. Notice how: 1. This is all devm-maganaged 2.
    The hidpp-battery.desc struct is shared between the 2 power supplies 3. hidpp-
    battery.desc.properties points to the result from the second devm_kmemdup() This causes a use after
    free scenario on USB disconnect of the receiver: 1. The last registered power supply class device gets
    unregistered 2. The memory from the last devm_kmemdup() call gets freed, hidpp-battery.desc.properties
    now points to freed memory 3. The first registered power supply class device gets unregistered, this
    involves sending a remove uevent to userspace which invokes power_supply_uevent() to fill the uevent data
    4. power_supply_uevent() uses hidpp-battery.desc.properties which now points to freed memory leading to
    backtraces like this one: Sep 22 20:01:35 eric kernel: BUG: unable to handle page fault for address:
    ffffb2140e017f08 ... Sep 22 20:01:35 eric kernel: Workqueue: usb_hub_wq hub_event Sep 22 20:01:35 eric
    kernel: RIP: 0010:power_supply_uevent+0xee/0x1d0 ... Sep 22 20:01:35 eric kernel: ?
    asm_exc_page_fault+0x26/0x30 Sep 22 20:01:35 eric kernel: ? power_supply_uevent+0xee/0x1d0 Sep 22 20:01:35
    eric kernel: ? power_supply_uevent+0x10d/0x1d0 Sep 22 20:01:35 eric kernel: dev_uevent+0x10f/0x2d0 Sep 22
    20:01:35 eric kernel: kobject_uevent_env+0x291/0x680 Sep 22 20:01:35 eric kernel:
    ---truncated---(CVE-2023-52478)

    In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in
    arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued,
    arp_req_get() looks up an neighbour entry and copies neigh-ha to struct arpreq.arp_ha.sa_data. The
    arp_ha here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In
    the splat below, 2 bytes are overflown to the next int field, arp_flags. We initialise the field just
    after the memcpy(), so it's not a problem. However, when dev-addr_len is greater than 22 (e.g.
    MAX_ADDR_LEN), arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL) in arp_ioctl() before
    calling arp_req_get(). To avoid the overflow, let's limit the max length of memcpy().(CVE-2024-26733)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/qedr: Fix qedr_create_user_qp
    error flow Avoid the following warning by making sure to free the allocated resources in case that
    qedr_init_user_queue() fail.(CVE-2024-26743)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Support specifying the
    srpt_service_guid parameter Make loading ib_srpt with this parameter set work. The current behavior is
    that setting that parameter while loading the ib_srpt kernel module triggers the following kernel crash:
    BUG: kernel NULL pointer dereference, address: 0000000000000000(CVE-2024-26744)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: make sure to pull inner
    header in __ip6_tnl_rcv() syzbot found __ip6_tnl_rcv() could access unitiliazed data [1]. Call
    pskb_inet_may_pull() to fix this, and initialize ipv6h variable after this call as it can change skb-
    head.(CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved: fs/proc: do_task_stat: use sig-
    stats_lock to gather the threads/children stats lock_task_sighand() can trigger a hard lockup. If
    NR_CPUS threads call do_task_stat() at the same time and the process has NR_THREADS, it will spin with
    irqs disabled O(NR_CPUS * NR_THREADS) time. Change do_task_stat() to use sig-stats_lock to gather the
    statistics outside of -siglock protected section, in the likely case this code will run
    lockless.(CVE-2024-26686)

    In the Linux kernel, the following vulnerability has been resolved: ppp_async: limit MRU to 64K syzbot
    triggered a warning [1] in __alloc_pages(): WARN_ON_ONCE_GFP(order  MAX_PAGE_ORDER, gfp) Willem fixed a
    similar issue in commit c0a2a1b0d631 (''ppp: limit MRU to 64K'') Adopt the same sanity check for
    ppp_async_ioctl(PPPIOCSMRU)(CVE-2024-26675)

    create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero
    bytes, and crash, because of a missing check for ubi-leb_size.(CVE-2024-25739)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Stop looking for coalesced MMIO
    zones if the bus is destroyed Abort the walk of coalesced MMIO zones if kvm_io_bus_unregister_dev() fails
    to allocate memory for the new instance of the bus. If it can't instantiate a new bus, unregister_dev()
    destroys all devices _except_ the target device. But, it doesn't tell the caller that it obliterated the
    bus and invoked the destructor for all devices that were on the bus. In the coalesced MMIO case, this can
    result in a deleted list entry dereference due to attempting to continue iterating on coalesced_zones
    after future entries (in the walk) have been deleted. Opportunistically add curly braces to the for-loop,
    which encompasses many lines but sneaks by without braces due to the guts being a single if
    statement.(CVE-2021-47060)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: don't override
    retval if we already lost the skb If we're redirecting the skb, and haven't called tcf_mirred_forward(),
    yet, we need to tell the core to drop the skb by setting the retcode to SHOT. If we have called
    tcf_mirred_forward(), however, the skb is out of our hands and returning SHOT will lead to UaF. Move the
    retval override to the error path which actually need it.(CVE-2024-26739)

    In the Linux kernel, the following vulnerability has been resolved: HID: usbhid: fix info leak in
    hid_submit_ctrl In hid_submit_ctrl(), the way of calculating the report length doesn't take into account
    that report-size can be zero. When running the syzkaller reproducer, a report of size 0 causes
    hid_submit_ctrl) to calculate transfer_buffer_length as 16384. When this urb is passed to the usb core
    layer, KMSAN reports an info leak of 16384 bytes. To fix this, first modify hid_report_len() to account
    for the zero report size case by using DIV_ROUND_UP for the division. Then, call it from
    hid_submit_ctrl().(CVE-2021-46906)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix hashtab overflow check on
    32-bit arches The hashtab code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. So apply the same fix to hashtab, by
    moving the overflow check to before the roundup.(CVE-2024-26884)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/amdgpu: fix refcount leak
    [Why] the gem object rfb-base.obj[0] is get according to num_planes in amdgpufb_create, but is not put
    according to num_planes [How] put rfb-base.obj[0] in amdgpu_fbdev_destroy according to
    num_planes(CVE-2021-47144)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Restructure
    trace_clock_global() to never block It was reported that a fix to the ring buffer recursion detection
    would cause a hung machine when performing suspend / resume testing.(CVE-2021-46939)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_limit: reject
    configurations that cause integer overflow Reject bogus configs where internal token counter wraps around.
    This only occurs with very very large requests, such as 17gbyte/s. Its better to reject this rather than
    having incorrect ratelimit.(CVE-2024-26668)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: processor_idle: Fix memory leak
    in acpi_processor_power_exit() After unregistering the CPU idle device, the memory associated with it is
    not freed, leading to a memory leak: unreferenced object 0xffff896282f6c000 (size 1024): comm
    ''swapper/0'', pid 1, jiffies 4294893170 hex dump (first 32 bytes): 00 00 00 00 0b 00 00 00 00 00 00 00 00
    00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc
    8836a742): [ffffffff993495ed] kmalloc_trace+0x29d/0x340 [ffffffff9972f3b3]
    acpi_processor_power_init+0xf3/0x1c0 [ffffffff9972d263] __acpi_processor_start+0xd3/0xf0
    [ffffffff9972d2bc] acpi_processor_start+0x2c/0x50 [ffffffff99805872] really_probe+0xe2/0x480
    [ffffffff99805c98] __driver_probe_device+0x78/0x160 [ffffffff99805daf]
    driver_probe_device+0x1f/0x90 [ffffffff9980601e] __driver_attach+0xce/0x1c0 [ffffffff99803170]
    bus_for_each_dev+0x70/0xc0 [ffffffff99804822] bus_add_driver+0x112/0x210 [ffffffff99807245]
    driver_register+0x55/0x100 [ffffffff9aee4acb] acpi_processor_driver_init+0x3b/0xc0
    [ffffffff990012d1] do_one_initcall+0x41/0x300 [ffffffff9ae7c4b0]
    kernel_init_freeable+0x320/0x470 [ffffffff99b231f6] kernel_init+0x16/0x1b0 [ffffffff99042e6d]
    ret_from_fork+0x2d/0x50 Fix this by freeing the CPU idle device after unregistering(CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved: ext4: fix double-free of blocks due to
    wrong extents moved_len In ext4_move_extents(), moved_len is only updated when all moves are successfully
    executed, and only discards orig_inode and donor_inode preallocations when moved_len is not zero. When the
    loop fails to exit after successfully moving some extents, moved_len is not updated and remains at 0, so
    it does not discard the preallocations. If the moved extents overlap with the preallocated extents, the
    overlapped extents are freed twice in ext4_mb_release_inode_pa() and ext4_process_freed_data() (as
    described in commit 94d7c16cbbbd (''ext4: Fix double-free of blocks with EXT4_IOC_MOVE_EXT'')), and
    bb_free is incremented twice. Hence when trim is executed, a zero-division bug is triggered in
    mb_update_avg_fragment_size() because bb_free is not zero and bb_fragments is zero. Therefore, update
    move_len after each extent move to avoid the issue.(CVE-2024-26704)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_conntrack_h323: Add
    protection for bmp length out of range UBSAN load reports an exception of BRK#5515 SHIFT_ISSUE:Bitwise
    shifts that are out of bounds for their data type.(CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Lock external INTx masking
    ops Mask operations through config space changes to DisINTx may race INTx configuration changes via ioctl.
    Create wrappers that add locking for paths outside of the core interrupt code. In particular, irq_type is
    updated holding igate, therefore testing is_intx() requires holding igate. For example clearing DisINTx
    from config space can otherwise race changes of the interrupt configuration. This aligns interfaces which
    may trigger the INTx eventfd into two camps, one side serialized by igate and the other only enabled while
    INTx is configured. A subsequent patch introduces synchronization for the latter flows.(CVE-2024-26810)

    In the Linux kernel, the following vulnerability has been resolved: cfg80211: call cfg80211_stop_ap when
    switch from P2P_GO type If the userspace tools switch from NL80211_IFTYPE_P2P_GO to NL80211_IFTYPE_ADHOC
    via send_msg(NL80211_CMD_SET_INTERFACE), it does not call the cleanup cfg80211_stop_ap(), this leads to
    the initialization of in-use data. For example, this path re-init the sdata-assigned_chanctx_list while
    it is still an element of assigned_vifs list, and makes that linked list corrupt.(CVE-2021-47194)

    In the Linux kernel, the following vulnerability has been resolved:vfio/pci: Disable auto-enable of
    exclusive INTx IRQ.Currently for devices requiring masking at the irqchip for INTx, ie. devices without
    DisINTx support, the IRQ is enabled in request_irq() and subsequently disabled as necessary to align with
    the masked status flag.  This presents a window where the interrupt could fire between these events,
    resulting in the IRQ incrementing the disable depth twice.This would be unrecoverable for a user since the
    masked flag prevents nested enables through vfio.Instead, invert the logic using IRQF_NO_AUTOEN such that
    exclusive INTx is never auto-enabled, then unmask as required.(CVE-2024-27437)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Do not register event
    handler until srpt device is fully setup Upon rare occasions, KASAN reports a use-after-free Write in
    srpt_refresh_port(). This seems to be because an event handler is registered before the srpt device is
    fully setup and a race condition upon error may leave a partially setup event handler in place. Instead,
    only register the event handler after srpt device initialization is complete.(CVE-2024-26872)

    In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix memory leak in
    cachefiles_add_cache()(CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Reset IH OVERFLOW_CLEAR
    bit Allows us to detect subsequent IH ring buffer overflows as well.(CVE-2024-26915)

    In the Linux kernel, the following vulnerability has been resolved: vfio/platform: Create persistent IRQ
    handlers The vfio-platform SET_IRQS ioctl currently allows loopback triggering of an interrupt before a
    signaling eventfd has been configured by the user, which thereby allows a NULL pointer dereference. Rather
    than register the IRQ relative to a valid trigger, register all IRQs in a disabled state in the device
    open path. This allows mask operations on the IRQ to nest within the overall enable state governed by a
    valid eventfd signal. This decouples @masked, protected by the @locked spinlock from @trigger, protected
    via the @igate mutex. In doing so, it's guaranteed that changes to @trigger cannot race the IRQ handlers
    because the IRQ handler is synchronously disabled before modifying the trigger, and loopback triggering of
    the IRQ via ioctl is safe due to serialization with trigger changes via igate. For compatibility,
    request_irq() failures are maintained to be local to the SET_IRQS ioctl rather than a fatal error in the
    open device path. This allows, for example, a userspace driver with polling mode support to continue to
    work regardless of moving the request_irq() call site. This necessarily blocks all SET_IRQS access to the
    failed index.(CVE-2024-26813)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: make sure to pull
    inner header in ip_tunnel_rcv() Apply the same fix than ones found in : 8d975c15c0cd (''ip6_tunnel: make
    sure to pull inner header in __ip6_tnl_rcv()'') 1ca1ba465e55 (''geneve: make sure to pull inner header in
    geneve_rx()'') We have to save skb-network_header in a temporary variable in order to be able to
    recompute the network_header pointer after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure
    the needed headers are in skb-head.(CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved: net/bnx2x: Prevent access to a freed
    page in page_pool Fix race condition leading to system crash during EEH error handling During EEH error
    recovery, the bnx2x driver's transmit timeout logic could cause a race condition when handling reset
    tasks. The bnx2x_tx_timeout() schedules reset tasks via bnx2x_sp_rtnl_task(), which ultimately leads to
    bnx2x_nic_unload(). In bnx2x_nic_unload() SGEs are freed using bnx2x_free_rx_sge_range(). However, this
    could overlap with the EEH driver's attempt to reset the device using bnx2x_io_slot_reset(), which also
    tries to free SGEs.(CVE-2024-26859)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Create persistent INTx
    handler A vulnerability exists where the eventfd for INTx signaling can be deconfigured, which unregisters
    the IRQ handler but still allows eventfds to be signaled with a NULL context through the SET_IRQS ioctl or
    through unmask irqfd if the device interrupt is pending. Ideally this could be solved with some additional
    locking; the igate mutex serializes the ioctl and config space accesses, and the interrupt handler is
    unregistered relative to the trigger, but the irqfd path runs asynchronous to those. The igate mutex
    cannot be acquired from the atomic context of the eventfd wake function. Disabling the irqfd relative to
    the eventfd registration is potentially incompatible with existing userspace. As a result, the solution
    implemented here moves configuration of the INTx interrupt handler to track the lifetime of the INTx
    context object and irq_type configuration, rather than registration of a particular trigger eventfd.
    Synchronization is added between the ioctl path and eventfd_signal() wrapper such that the eventfd trigger
    can be dynamically updated relative to in-flight interrupts or irqfd callbacks.(CVE-2024-26812)

    In the Linux kernel, the following vulnerability has been resolved: team: fix null-ptr-deref when team
    device type is changed Get a null-ptr-deref bug as follows with reproducer [1]. BUG: kernel NULL pointer
    dereference, address: 0000000000000228 ... RIP: 0010:vlan_dev_hard_header+0x35/0x140 [8021q] ... Call
    Trace: TASK ? __die+0x24/0x70 ? page_fault_oops+0x82/0x150 ? exc_page_fault+0x69/0x150 ?
    asm_exc_page_fault+0x26/0x30 ? vlan_dev_hard_header+0x35/0x140 [8021q] ? vlan_dev_hard_header+0x8e/0x140
    [8021q] neigh_connected_output+0xb2/0x100 ip6_finish_output2+0x1cb/0x520 ? nf_hook_slow+0x43/0xc0 ?
    ip6_mtu+0x46/0x80 ip6_finish_output+0x2a/0xb0 mld_sendpack+0x18f/0x250 mld_ifc_work+0x39/0x160
    process_one_work+0x1e6/0x3f0 worker_thread+0x4d/0x2f0 ? __pfx_worker_thread+0x10/0x10 kthread+0xe5/0x120 ?
    __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 [1]
    $ teamd -t team0 -d -c '{''runner'': {''name'': ''loadbalance''}}' $ ip link add name t-dummy type dummy $
    ip link add link t-dummy name t-dummy.100 type vlan id 100 $ ip link add name t-nlmon type nlmon $ ip link
    set t-nlmon master team0 $ ip link set t-nlmon nomaster $ ip link set t-dummy up $ ip link set team0 up $
    ip link set t-dummy.100 down $ ip link set t-dummy.100 master team0 When enslave a vlan device to team
    device and team device type is changed from non-ether to ether, header_ops of team device is changed to
    vlan_header_ops. That is incorrect and will trigger null-ptr-deref for vlan-real_dev in
    vlan_dev_hard_header() because team device is not a vlan device. Cache eth_header_ops in team_setup(),
    then assign cached header_ops to header_ops of team net device when its type is changed from non-ether to
    ether to fix the bug.(CVE-2023-52574)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: validate the parameters of
    bo mapping operations more clearly Verify the parameters of
    amdgpu_vm_bo_(map/replace_map/clearing_mappings) in one common place.(CVE-2024-26922)

    In the Linux kernel, the following vulnerability has been resolved: cifs: fix underflow in
    parse_server_interfaces() In this loop, we step through the buffer and after each item we check if the
    size_left is greater than the minimum size we need. However, the problem is that ''bytes_left'' is type
    ssize_t while sizeof() is type size_t. That means that because of type promotion, the comparison is done
    as an unsigned and if we have negative bytes left the loop continues instead of ending.(CVE-2024-26828)

    In the Linux kernel, the following vulnerability has been resolved: do_sys_name_to_handle(): use kzalloc()
    to fix kernel-infoleak syzbot identified a kernel information leak vulnerability in
    do_sys_name_to_handle() and issued the following report [1]. [1] ''BUG: KMSAN: kernel-infoleak in
    instrument_copy_to_user include/linux/instrumented.h:114 [inline] BUG: KMSAN: kernel-infoleak in
    _copy_to_user+0xbc/0x100 lib/usercopy.c:40 instrument_copy_to_user include/linux/instrumented.h:114
    [inline] _copy_to_user+0xbc/0x100 lib/usercopy.c:40 copy_to_user include/linux/uaccess.h:191 [inline]
    do_sys_name_to_handle fs/fhandle.c:73 [inline] __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
    __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94 __x64_sys_name_to_handle_at+0xe4/0x140
    fs/fhandle.c:94 ... Uninit was created at: slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768 slab_alloc_node
    mm/slub.c:3478 [inline] __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517 __do_kmalloc_node
    mm/slab_common.c:1006 [inline] __kmalloc+0x121/0x3c0 mm/slab_common.c:1020 kmalloc
    include/linux/slab.h:604 [inline] do_sys_name_to_handle fs/fhandle.c:39 [inline]
    __do_sys_name_to_handle_at fs/fhandle.c:112 [inline] __se_sys_name_to_handle_at+0x441/0xb10
    fs/fhandle.c:94 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94 ... Bytes 18-19 of 20 are
    uninitialized Memory access of size 20 starts at ffff888128a46380 Data copied to user address
    0000000020000240'' Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to solve the
    problem.(CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix scsi_mode_sense()
    buffer length handling Several problems exist with scsi_mode_sense() buffer length handling: 1) The
    allocation length field of the MODE SENSE(10) command is 16-bits, occupying bytes 7 and 8 of the CDB. With
    this command, access to mode pages larger than 255 bytes is thus possible. However, the CDB allocation
    length field is set by assigning len to byte 8 only, thus truncating buffer length larger than 255. 2) If
    scsi_mode_sense() is called with len smaller than 8 with sdev-use_10_for_ms set, or smaller than 4
    otherwise, the buffer length is increased to 8 and 4 respectively, and the buffer is zero filled with
    these increased values, thus corrupting the memory following the buffer. Fix these 2 problems by using
    put_unaligned_be16() to set the allocation length field of MODE SENSE(10) CDB and by returning an error
    when len is too small. Furthermore, if len is larger than 255B, always try MODE SENSE(10) first, even if
    the device driver did not set sdev-use_10_for_ms. In case of invalid opcode error for MODE SENSE(10),
    access to mode pages larger than 255 bytes are not retried using MODE SENSE(6). To avoid buffer length
    overflows for the MODE_SENSE(10) case, check that len is smaller than 65535 bytes. While at it, also fix
    the folowing: * Use get_unaligned_be16() to retrieve the mode data length and block descriptor length
    fields of the mode sense reply header instead of using an open coded calculation. * Fix the kdoc dbd
    argument explanation: the DBD bit stands for Disable Block Descriptor, which is the opposite of what the
    dbd argument description was.(CVE-2021-47182)

    A null pointer dereference vulnerability was found in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() in
    drivers/net/wireless/ath/ath10k/wmi-tlv.c in the Linux kernel. This issue could be exploited to trigger a
    denial of service.(CVE-2023-7042)

    In the Linux kernel, the following vulnerability has been resolved: net: qualcomm: rmnet: fix global oob
    in rmnet_policy The variable rmnet_link_ops assign a *bigger* maxtype which leads to a global out-of-
    bounds read when parsing the netlink attributes.(CVE-2024-26597)

    In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in
    tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev-tstats and tun-security
    allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is
    paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the
    destructor will handle the frees.(CVE-2021-47082)

    In the Linux kernel, the following vulnerability has been resolved: scsi: target: core: Add TMF to
    tmr_list handling An abort that is responded to by iSCSI itself is added to tmr_list but does not go to
    target core. A LUN_RESET that goes through tmr_list takes a refcounter on the abort and waits for
    completion. However, the abort will be never complete because it was not started in target
    core.(CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix stackmap overflow check on
    32-bit arches The stackmap code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. The commit in the fixes tag actually
    attempted to fix this, but the fix did not account for the UB, so the fix only works on CPUs where an
    overflow does result in a neat truncation to zero, which is not guaranteed. Checking the value before
    rounding does not have this problem.(CVE-2024-26883)

    In the Linux kernel, the following vulnerability has been resolved: tcp: make sure init the accept_queue's
    spinlocks once When I run syz's reproduction C program locally, it causes the following issue:
    pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0!(CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved: wifi: rt2x00: restart beacon queue
    when hardware reset When a hardware reset is triggered, all registers are reset, so all queues are forced
    to stop in hardware interface. However, mac80211 will not automatically stop the queue. If we don't
    manually stop the beacon queue, the queue will be deadlocked and unable to start again. This patch fixes
    the issue where Apple devices cannot connect to the AP after calling
    ieee80211_restart_hw().(CVE-2023-52595)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2038
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8db1e29");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-devel-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-headers-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-tools-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "python-perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "python3-perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
