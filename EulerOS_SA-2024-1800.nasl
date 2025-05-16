#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198320);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id(
    "CVE-2021-47036",
    "CVE-2021-47082",
    "CVE-2022-48627",
    "CVE-2023-52340",
    "CVE-2023-52434",
    "CVE-2023-52435",
    "CVE-2023-52438",
    "CVE-2023-52439",
    "CVE-2023-52443",
    "CVE-2023-52445",
    "CVE-2023-52447",
    "CVE-2023-52448",
    "CVE-2023-52451",
    "CVE-2023-52452",
    "CVE-2023-52454",
    "CVE-2023-52458",
    "CVE-2023-52462",
    "CVE-2023-52463",
    "CVE-2023-52464",
    "CVE-2023-52469",
    "CVE-2023-52474",
    "CVE-2023-52475",
    "CVE-2023-52477",
    "CVE-2023-52482",
    "CVE-2023-52504",
    "CVE-2023-52516",
    "CVE-2023-52528",
    "CVE-2023-52568",
    "CVE-2023-52575",
    "CVE-2024-0841",
    "CVE-2024-1086",
    "CVE-2024-1151",
    "CVE-2024-26581",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26586",
    "CVE-2024-26589",
    "CVE-2024-26593",
    "CVE-2024-26595",
    "CVE-2024-26597",
    "CVE-2024-26598",
    "CVE-2024-26601",
    "CVE-2024-26602",
    "CVE-2024-26603",
    "CVE-2024-26606"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2024-1800)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-its: Avoid potential
    UAF in LPI translation cache There is a potential UAF scenario in the case of an LPI translation cache hit
    racing with an operation that invalidates the cache, such as a DISCARD ITS command. The root of the
    problem is that vgic_its_check_cache() does not elevate the refcount on the vgic_irq before dropping the
    lock that serializes refcount changes. Have vgic_its_check_cache() raise the refcount on the returned
    vgic_irq and add the corresponding decrement after queueing the interrupt.(CVE-2024-26598)

    In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in
    tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev-tstats and tun-security
    allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is
    paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the
    destructor will handle the frees.(CVE-2021-47082)

    In the Linux kernel, the following vulnerability has been resolved: vt: fix memory overlapping when
    deleting chars in the buffer A memory overlapping copy occurs when deleting a long line. This memory
    overlapping copy can cause data corruption when scr_memcpyw is optimized to memcpy because memcpy does not
    ensure its behavior if the destination buffer overlaps with the source buffer. The line buffer is not
    always broken, because the memcpy utilizes the hardware acceleration, whose result is not deterministic.
    Fix this problem by using replacing the scr_memcpyw with scr_memmovew.(CVE-2022-48627)

    A flaw was found in hfi1 in the Linux Kernel. This issue is due to data corruption for user SDMA requests
    that have multiple payload iovecs where an iovec other than the tail iovec does not run up to the page
    boundary.(CVE-2023-52474)

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

    In the Linux kernel, the following vulnerability has been resolved:x86/srso: Add SRSO mitigation for Hygon
    processors Add mitigation for the speculative return stack overflow vulnerability which exists on Hygon
    processors too.(CVE-2023-52482)

    In the Linux kernel, the following vulnerability has been resolved:x86/srso: Fix SBPB enablement for
    spec_rstack_overflow=off If the user has requested no SRSO mitigation, other mitigations can use the
    lighter-weight SBPB instead of IBPB.(CVE-2023-52575)

    A flaw in the routing table size was found in the ICMPv6 handling of quot;Packet Too Bigquot;. The
    size of the routing table is regulated by periodic garbage collection. However, with quot;Packet Too
    Big Messagesquot; it is possible to exceed the routing table size and garbage collector threshold. A
    user located in the local network or with a high bandwidth connection can increase the CPU usage of the
    server that accepts IPV6 connections up to 95%.(CVE-2023-52340)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit
    f342de4e2f33e0e39165d8639387aa6c19dff660.(CVE-2024-1086)

    In the Linux kernel, the following vulnerability has been resolved:binder: signal epoll threads of self-
    work In (e)poll mode, threads often depend on I/O events to determine when data is ready for consumption.
    Within binder, a thread may initiate a command via BINDER_WRITE_READ without a read buffer and then make
    use of epoll_wait() or similar to consume any responses afterwards.It is then crucial that epoll threads
    are signaled via wakeup when they queue their own work. Otherwise, they risk waiting indefinitely for an
    event leaving their work unhandled. What is worse, subsequent commands won't trigger a wakeup either as
    the thread has pending work.(CVE-2024-26606)

    In the Linux kernel, the following vulnerability has been resolved: x86/fpu: Stop relying on userspace for
    info to fault in xsave buffer Before this change, the expected size of the user space buffer was taken
    from fx_sw-xstate_size. fx_sw-xstate_size can be changed from user-space, so it is possible
    construct a sigreturn frame where: * fx_sw-xstate_size is smaller than the size required by valid bits
    in fx_sw-xfeatures. * user-space unmaps parts of the sigrame fpu buffer so that not all of the buffer
    required by xrstor is accessible. In this case, xrstor tries to restore and accesses the unmapped area
    which results in a fault. But fault_in_readable succeeds because buf + fx_sw-xstate_size is within the
    still mapped area, so it goes back and tries xrstor again. It will spin in this loop forever. Instead,
    fault in the maximum size which can be touched by XRSTOR (taken from fpstate-
    user_size).(CVE-2024-26603)

    In the Linux kernel, the following vulnerability has been resolved:sched/membarrier: reduce the ability to
    hammer on sys_membarrier On some systems, sys_membarrier can be very expensive, causing overall slowdowns
    for everything.  So put a lock on the path in order to serialize the accesses to prevent the ability for
    this to be called at too high of a frequency and saturate the machine.(CVE-2024-26602)

    In the Linux kernel, the following vulnerability has been resolved:ext4: regenerate buddy after block
    freeing failed if under fc replay This mostly reverts commit 6bd97bf273bd ('ext4: remove redundant
    mb_regenerate_buddy()') and reintroduces mb_regenerate_buddy(). Based on code in mb_free_blocks(), fast
    commit replay can end up marking as free blocks that are already marked as such. This causes corruption of
    the buddy bitmap so we need to regenerate it in that case.(CVE-2024-26601)

    In the Linux kernel, the following vulnerability has been resolved: net: qualcomm: rmnet: fix global oob
    in rmnet_policy The variable rmnet_link_ops assign a *bigger* maxtype which leads to a global out-of-
    bounds read when parsing the netlink attributes. See bug trace below:
    ================================================================== BUG: KASAN: global-out-of-bounds in
    validate_nla lib/nlattr.c:386 [inline] BUG: KASAN: global-out-of-bounds in
    __nla_validate_parse+0x24af/0x2750 lib/nlattr.c:600 Read of size 1 at addr ffffffff92c438d0 by task syz-
    executor.6/84207 CPU: 0 PID: 84207 Comm: syz-executor.6 Tainted: G N 6.1.0 #3 Hardware name: QEMU Standard
    PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014 Call Trace: TASK __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0x8b/0xb3 lib/dump_stack.c:106 print_address_description
    mm/kasan/report.c:284 [inline] print_report+0x172/0x475 mm/kasan/report.c:395 kasan_report+0xbb/0x1c0
    mm/kasan/report.c:495 validate_nla lib/nlattr.c:386 [inline] __nla_validate_parse+0x24af/0x2750
    lib/nlattr.c:600 __nla_parse+0x3e/0x50 lib/nlattr.c:697 nla_parse_nested_deprecated
    include/net/netlink.h:1248 [inline] __rtnl_newlink+0x50a/0x1880 net/core/rtnetlink.c:3485
    rtnl_newlink+0x64/0xa0 net/core/rtnetlink.c:3594 rtnetlink_rcv_msg+0x43c/0xd70 net/core/rtnetlink.c:6091
    netlink_rcv_skb+0x14f/0x410 net/netlink/af_netlink.c:2540 netlink_unicast_kernel
    net/netlink/af_netlink.c:1319 [inline] netlink_unicast+0x54e/0x800 net/netlink/af_netlink.c:1345
    netlink_sendmsg+0x930/0xe50 net/netlink/af_netlink.c:1921 sock_sendmsg_nosec net/socket.c:714 [inline]
    sock_sendmsg+0x154/0x190 net/socket.c:734 ____sys_sendmsg+0x6df/0x840 net/socket.c:2482
    ___sys_sendmsg+0x110/0x1b0 net/socket.c:2536 __sys_sendmsg+0xf3/0x1c0 net/socket.c:2565 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3b/0x90 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x63/0xcd RIP: 0033:0x7fdcf2072359 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 f1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 48 3d
    01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fdcf13e3168 EFLAGS: 00000246
    ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007fdcf219ff80 RCX: 00007fdcf2072359 RDX:
    0000000000000000 RSI: 0000000020000200 RDI: 0000000000000003 RBP: 00007fdcf20bd493 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13:
    00007fffbb8d7bdf R14: 00007fdcf13e3300 R15: 0000000000022000 /TASK The buggy address belongs to the
    variable: rmnet_policy+0x30/0xe0 The buggy address belongs to the physical page: page:0000000065bdeb3c
    refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x155243 flags:
    0x200000000001000(reserved|node=0|zone=2) raw: 0200000000001000 ffffea00055490c8 ffffea00055490c8
    0000000000000000 raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000 page dumped
    because: kasan: bad access detected Memory state around the buggy address: ffffffff92c43780: f9 f9 f9 f9
    00 00 00 02 f9 f9 f9 f9 00 00 00 07 ffffffff92c43800: f9 f9 f9 f9 00 00 00 05 f9 f9 f9 f9 06 f9 f9 f9
    ffffffff92c43880: f9 f9 f9 f9 00 00 00 00 00 00 f9 f9 f9 f9 f9 f9 ^ ffffffff92c43900: 00 00 00 00 00 00
    00 00 07 f9 f9 f9 f9 f9 f9 f9 ffffffff92c43980: 00 00 00 07 f9 f9 f9 f9 00 00 00 05 f9 f9 f9 f9 According
    to the comment of `nla_parse_nested_deprecated`, the maxtype should be len(destination array) - 1. Hence
    use `IFLA_RMNET_MAX` here.(CVE-2024-26597)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix NULL
    pointer dereference in error path When calling mlxsw_sp_acl_tcam_region_destroy() from an error path after
    failing to attach the region to an ACL group, we hit a NULL pointer dereference upon 'region-group-
    tcam' [1]. Fix by retrieving the 'tcam' pointer using mlxsw_sp_acl_to_tcam(). [1] BUG: kernel NULL
    pointer dereference, address: 0000000000000000 [...] RIP: 0010:mlxsw_sp_acl_tcam_region_destroy+0xa0/0xd0
    [...] Call Trace: mlxsw_sp_acl_tcam_vchunk_get+0x88b/0xa20 mlxsw_sp_acl_tcam_ventry_add+0x25/0xe0
    mlxsw_sp_acl_rule_add+0x47/0x240 mlxsw_sp_flower_replace+0x1a9/0x1d0 tc_setup_cb_add+0xdc/0x1c0
    fl_hw_replace_filter+0x146/0x1f0 fl_change+0xc17/0x1360 tc_new_tfilter+0x472/0xb90
    rtnetlink_rcv_msg+0x313/0x3b0 netlink_rcv_skb+0x58/0x100 netlink_unicast+0x244/0x390
    netlink_sendmsg+0x1e4/0x440 ____sys_sendmsg+0x164/0x260 ___sys_sendmsg+0x9a/0xe0 __sys_sendmsg+0x7a/0xc0
    do_syscall_64+0x40/0xe0 entry_SYSCALL_64_after_hwframe+0x63/0x6b(CVE-2024-26595)

    In the Linux kernel, the following vulnerability has been resolved: i2c: i801: Fix block process call
    transactions According to the Intel datasheets, software must reset the block buffer index twice for block
    process call transactions: once before writing the outgoing data to the buffer, and once again before
    reading the incoming data from the buffer. The driver is currently missing the second reset, causing the
    wrong portion of the block buffer to be read.(CVE-2024-26593)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Reject variable offset alu on
    PTR_TO_FLOW_KEYS For PTR_TO_FLOW_KEYS, check_flow_keys_access() only uses fixed off for validation.
    However, variable offset ptr alu is not prohibited for this ptr kind. So the variable offset is not
    checked. The following prog is accepted: func#0 @0 0: R1=ctx() R10=fp0 0: (bf) r6 = r1 ; R1=ctx()
    R6_w=ctx() 1: (79) r7 = *(u64 *)(r6 +144) ; R6_w=ctx() R7_w=flow_keys() 2: (b7) r8 = 1024 ; R8_w=1024 3:
    (37) r8 /= 1 ; R8_w=scalar() 4: (57) r8 = 1024 ; R8_w=scalar(smin=smin32=0,
    smax=umax=smax32=umax32=1024,var_off=(0x0; 0x400)) 5: (0f) r7 += r8 mark_precise: frame0: last_idx 5
    first_idx 0 subseq_idx -1 mark_precise: frame0: regs=r8 stack= before 4: (57) r8 = 1024 mark_precise:
    frame0: regs=r8 stack= before 3: (37) r8 /= 1 mark_precise: frame0: regs=r8 stack= before 2: (b7) r8 =
    1024 6: R7_w=flow_keys(smin=smin32=0,smax=umax=smax32=umax32=1024,var_off =(0x0; 0x400))
    R8_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=1024, var_off=(0x0; 0x400)) 6: (79) r0 = *(u64 *)(r7 +0)
    ; R0_w=scalar() 7: (95) exit This prog loads flow_keys to r7, and adds the variable offset r8 to r7, and
    finally causes out-of-bounds access: BUG: unable to handle page fault for address: ffffc90014c80038 [...]
    Call Trace: TASK bpf_dispatcher_nop_func include/linux/bpf.h:1231 [inline] __bpf_prog_run
    include/linux/filter.h:651 [inline] bpf_prog_run include/linux/filter.h:658 [inline]
    bpf_prog_run_pin_on_cpu include/linux/filter.h:675 [inline] bpf_flow_dissect+0x15f/0x350
    net/core/flow_dissector.c:991 bpf_prog_test_run_flow_dissector+0x39d/0x620 net/bpf/test_run.c:1359
    bpf_prog_test_run kernel/bpf/syscall.c:4107 [inline] __sys_bpf+0xf8f/0x4560 kernel/bpf/syscall.c:5475
    __do_sys_bpf kernel/bpf/syscall.c:5561 [inline] __se_sys_bpf kernel/bpf/syscall.c:5559 [inline]
    __x64_sys_bpf+0x73/0xb0 kernel/bpf/syscall.c:5559 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0x3f/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b Fix this by
    rejecting ptr alu with variable offset on flow_keys. Applying the patch rejects the program with 'R7
    pointer arithmetic on flow_keys prohibited'.(CVE-2024-26589)

    In the Linux kernel, the following vulnerability has been resolved:mlxsw: spectrum_acl_tcam: Fix stack
    corruption When tc filters are first added to a net device, the corresponding local port gets bound to an
    ACL group in the device. The group contains a list of ACLs.In turn, each ACL points to a different TCAM
    region where the filters are stored. During forwarding, the ACLs are sequentially evaluated until a match
    is found.One reason to place filters in different regions is when they are added with decreasing
    priorities and in an alternating order so that two consecutive filters can never fit in the same region
    because of their key usage.In Spectrum-2 and newer ASICs the firmware started to report that the maximum
    number of ACLs in a group is more than 16, but the layout of the register that configures ACL groups
    (PAGT) was not updated to account for that. It is therefore possible to hit stack corruption [1] in the
    rare case where more than 16 ACLs in a group are required.Fix by limiting the maximum ACL group size to
    the minimum between what the firmware reports and the maximum ACLs that fit in the PAGT register.Add a
    test case to make sure the machine does not crash when this condition is hit.(CVE-2024-26586)

    In the Linux kernel, the following vulnerability has been resolved:tls: fix race between tx work
    scheduling and socket close.Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit
    as soon as the async crypto handler calls complete().Reorder scheduling the work before calling
    complete().This seems more logical in the first place, as it's
    the inverse order of what the submitting thread will do.(CVE-2024-26585)

    In the Linux kernel, the following vulnerability has been resolved:net: tls: handle backlogging of crypto
    requests.Since we're setting the CRYPTO_TFM_REQ_MAY_BACKLOG flag on our requests to the crypto API,
    crypto_aead_{encrypt,decrypt} can return  -EBUSY instead of -EINPROGRESS in valid situations. For example,
    when the cryptd queue for AESNI is full (easy to trigger with an artificially low
    cryptd.cryptd_max_cpu_qlen), requests will be enqueued to the backlog but still processed. In that case,
    the async callback will also be called twice: first with err == -EINPROGRESS, which it seems we can just
    ignore, then with err == 0.Compared to Sabrina's original patch this version uses the new
    tls_*crypt_async_wait() helpers and converts the EBUSY to EINPROGRESS to avoid having to modify all the
    error handling paths. The handling is identical.(CVE-2024-26584)

    In the Linux kernel, the following vulnerability has been resolved:tls: fix race between async notify and
    socket close.The submitting thread (one which called recvmsg/sendmsg) may exit as soon as the async crypto
    handler calls complete() so any code past that point risks touching already freed data.Try to avoid the
    locking and extra flags altogether.Have the main thread hold an extra reference, this way we can depend
    solely on the atomic ref counter for synchronization.Don't futz with reiniting the completion, either, we
    are now tightly controlling when completion fires.(CVE-2024-26583)

    In the Linux kernel, the following vulnerability has been resolved:netfilter: nft_set_rbtree: skip end
    interval element from gc.rbtree lazy gc on insert might collect an end interval element that has
    been just added in this transactions, skip end interval elements that are not yet active.(CVE-2024-26581)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    In the Linux kernel, the following vulnerability has been resolved:x86/sgx: Resolves SECS reclaim vs.page
    fault for EAUG race The SGX EPC reclaimer (ksgxd) may reclaim the SECS EPC page for an enclave and set
    secs.epc_page to NULL. The SECS page is used for EAUG and ELDU in the SGX page fault handler. However, the
    NULL check for secs.epc_page is only done for ELDU, not EAUG before being used.Fix this by doing the same
    NULL check and reloading of the SECS page as needed for both EAUG and ELDU.The SECS page holds global
    enclave metadata. It can only be reclaimed when there are no other enclave pages remaining. At that
    point,virtually nothing can be done with the enclave until the SECS page is paged back in.An enclave can
    not run nor generate page faults without a resident SECS page. But it is still possible for a #PF for a
    non-SECS page to race with paging out the SECS page: when the last resident non-SECS page A triggers a #PF
    in a non-resident page B, and then page A and the SECS both are paged out before the #PF on B is
    handled.Hitting this bug requires that race triggered with a #PF for EAUG.Following is a trace when it
    happens.(CVE-2023-52568)

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

    In the Linux kernel, the following vulnerability has been resolved: dma-debug: don't call
    __dma_entry_alloc_check_leak() under free_entries_lock __dma_entry_alloc_check_leak() calls into printk
    - serial console output (qcom geni) and grabs port-lock under free_entries_lock spin lock, which is
    a reverse locking dependency chain as qcom_geni IRQ handler can call into dma-debug code and grab
    free_entries_lock under port-lock. Move __dma_entry_alloc_check_leak() call out of free_entries_lock
    scope so that we don't acquire serial console's port-lock under it. Trimmed-down lockdep splat: The
    existing dependency chain (in reverse order) is: - #2 (free_entries_lock){-.-.}-{2:2}:
    _raw_spin_lock_irqsave+0x60/0x80 dma_entry_alloc+0x38/0x110 debug_dma_map_page+0x60/0xf8
    dma_map_page_attrs+0x1e0/0x230 dma_map_single_attrs.constprop.0+0x6c/0xc8 geni_se_rx_dma_prep+0x40/0xcc
    qcom_geni_serial_isr+0x310/0x510 __handle_irq_event_percpu+0x110/0x244 handle_irq_event_percpu+0x20/0x54
    handle_irq_event+0x50/0x88 handle_fasteoi_irq+0xa4/0xcc handle_irq_desc+0x28/0x40
    generic_handle_domain_irq+0x24/0x30 gic_handle_irq+0xc4/0x148 do_interrupt_handler+0xa4/0xb0
    el1_interrupt+0x34/0x64 el1h_64_irq_handler+0x18/0x24 el1h_64_irq+0x64/0x68 arch_local_irq_enable+0x4/0x8
    ____do_softirq+0x18/0x24 ... - #1 (port_lock_key){-.-.}-{2:2}: _raw_spin_lock_irqsave+0x60/0x80
    qcom_geni_serial_console_write+0x184/0x1dc console_flush_all+0x344/0x454 console_unlock+0x94/0xf0
    vprintk_emit+0x238/0x24c vprintk_default+0x3c/0x48 vprintk+0xb4/0xbc _printk+0x68/0x90
    register_console+0x230/0x38c uart_add_one_port+0x338/0x494 qcom_geni_serial_probe+0x390/0x424
    platform_probe+0x70/0xc0 really_probe+0x148/0x280 __driver_probe_device+0xfc/0x114
    driver_probe_device+0x44/0x100 __device_attach_driver+0x64/0xdc bus_for_each_drv+0xb0/0xd8
    __device_attach+0xe4/0x140 device_initial_probe+0x1c/0x28 bus_probe_device+0x44/0xb0
    device_add+0x538/0x668 of_device_add+0x44/0x50 of_platform_device_create_pdata+0x94/0xc8
    of_platform_bus_create+0x270/0x304 of_platform_populate+0xac/0xc4 devm_of_platform_populate+0x60/0xac
    geni_se_probe+0x154/0x160 platform_probe+0x70/0xc0 ... - #0 (console_owner){-...}-{0:0}:
    __lock_acquire+0xdf8/0x109c lock_acquire+0x234/0x284 console_flush_all+0x330/0x454
    console_unlock+0x94/0xf0 vprintk_emit+0x238/0x24c vprintk_default+0x3c/0x48 vprintk+0xb4/0xbc
    _printk+0x68/0x90 dma_entry_alloc+0xb4/0x110 debug_dma_map_sg+0xdc/0x2f8 __dma_map_sg_attrs+0xac/0xe4
    dma_map_sgtable+0x30/0x4c get_pages+0x1d4/0x1e4 [msm] msm_gem_pin_pages_locked+0x38/0xac [msm]
    msm_gem_pin_vma_locked+0x58/0x88 [msm] msm_ioctl_gem_submit+0xde4/0x13ac [msm] drm_ioctl_kernel+0xe0/0x15c
    drm_ioctl+0x2e8/0x3f4 vfs_ioctl+0x30/0x50 ... Chain exists of: console_owner -- port_lock_key --
    free_entries_lock Possible unsafe locking scenario: CPU0 CPU1 ---- ---- lock(free_entries_lock);
    lock(port_lock_key); lock(free_entries_lock); lock(console_owner); *** DEADLOCK *** Call trace:
    dump_backtrace+0xb4/0xf0 show_stack+0x20/0x30 dump_stack_lvl+0x60/0x84 dump_stack+0x18/0x24
    print_circular_bug+0x1cc/0x234 check_noncircular+0x78/0xac __lock_acquire+0xdf8/0x109c
    lock_acquire+0x234/0x284 console_flush_all+0x330/0x454 consol ---truncated---(CVE-2023-52516)

    In the Linux kernel, the following vulnerability has been resolved: x86/alternatives: Disable KASAN in
    apply_alternatives() Fei has reported that KASAN triggers during apply_alternatives() on a 5-level paging
    machine: BUG: KASAN: out-of-bounds in rcu_is_watching() Read of size 4 at addr ff110003ee6419a0 by task
    swapper/0/0 ... __asan_load4() rcu_is_watching() trace_hardirqs_on() text_poke_early()
    apply_alternatives() ... On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57) gets
    patched. It includes KASAN code, where KASAN_SHADOW_START depends on __VIRTUAL_MASK_SHIFT, which is
    defined with cpu_feature_enabled(). KASAN gets confused when apply_alternatives() patches the
    KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START static, by replacing
    __VIRTUAL_MASK_SHIFT with 56, works around the issue. Fix it for real by disabling KASAN while the kernel
    is patching alternatives.(CVE-2023-52504)

    In the Linux kernel, the following vulnerability has been resolved:Input: powermate - fix use-after-free
    in powermate_config_complete.syzbot has found a use-after-free bug [1] in the powermate driver. This
    happens when the device is disconnected, which leads to a memory free from the  powermate_device struct.
    When an asynchronous control message completes after the kfree and its callback is invoked, the lock does
    not exist anymore and hence the bug.Use usb_kill_urb() on pm-config to cancel any in-progress requests
    upondevice disconnection.(CVE-2023-52475)

    In the Linux kernel, the following vulnerability has been resolved: drivers/amd/pm: fix a use-after-free
    in kv_parse_power_table When ps allocated by kzalloc equals to NULL, kv_parse_power_table frees adev-
    pm.dpm.ps that allocated before. However, after the control flow goes through the following call
    chains: kv_parse_power_table |- kv_dpm_init |- kv_dpm_sw_init |- kv_dpm_fini The adev-
    pm.dpm.ps is used in the for loop of kv_dpm_fini after its first free in kv_parse_power_table and
    causes a use-after-free bug.( CVE-2023-52469)

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

    In the Linux kernel, the following vulnerability has been resolved: efivarfs: force RO when remounting if
    SetVariable is not supported If SetVariable at runtime is not supported by the firmware we never assign a
    callback for that function. At the same time mount the efivarfs as RO so no one can call that. However, we
    never check the permission flags when someone remounts the filesystem as RW. As a result this leads to a
    crash looking like this: $ mount -o remount,rw /sys/firmware/efi/efivars $ efi-updatevar -f PK.auth PK [
    303.279166] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 [
    303.280482] Mem abort info: [ 303.280854] ESR = 0x0000000086000004 [ 303.281338] EC = 0x21: IABT (current
    EL), IL = 32 bits [ 303.282016] SET = 0, FnV = 0 [ 303.282414] EA = 0, S1PTW = 0 [ 303.282821] FSC = 0x04:
    level 0 translation fault [ 303.283771] user pgtable: 4k pages, 48-bit VAs, pgdp=000000004258c000 [
    303.284913] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000 [ 303.286076] Internal error:
    Oops: 0000000086000004 [#1] PREEMPT SMP [ 303.286936] Modules linked in: qrtr tpm_tis tpm_tis_core
    crct10dif_ce arm_smccc_trng rng_core drm fuse ip_tables x_tables ipv6 [ 303.288586] CPU: 1 PID: 755 Comm:
    efi-updatevar Not tainted 6.3.0-rc1-00108-gc7d0c4695c68 #1 [ 303.289748] Hardware name: Unknown Unknown
    Product/Unknown Product, BIOS 2023.04-00627-g88336918701d 04/01/2023 [ 303.291150] pstate: 60400005 (nZCv
    daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) [ 303.292123] pc : 0x0 [ 303.292443] lr :
    efivar_set_variable_locked+0x74/0xec [ 303.293156] sp : ffff800008673c10 [ 303.293619] x29:
    ffff800008673c10 x28: ffff0000037e8000 x27: 0000000000000000 [ 303.294592] x26: 0000000000000800 x25:
    ffff000002467400 x24: 0000000000000027 [ 303.295572] x23: ffffd49ea9832000 x22: ffff0000020c9800 x21:
    ffff000002467000 [ 303.296566] x20: 0000000000000001 x19: 00000000000007fc x18: 0000000000000000 [
    303.297531] x17: 0000000000000000 x16: 0000000000000000 x15: 0000aaaac807ab54 [ 303.298495] x14:
    ed37489f673633c0 x13: 71c45c606de13f80 x12: 47464259e219acf4 [ 303.299453] x11: ffff000002af7b01 x10:
    0000000000000003 x9 : 0000000000000002 [ 303.300431] x8 : 0000000000000010 x7 : ffffd49ea8973230 x6 :
    0000000000a85201 [ 303.301412] x5 : 0000000000000000 x4 : ffff0000020c9800 x3 : 00000000000007fc [
    303.302370] x2 : 0000000000000027 x1 : ffff000002467400 x0 : ffff000002467000 [ 303.303341] Call trace: [
    303.303679] 0x0 [ 303.303938] efivar_entry_set_get_size+0x98/0x16c [ 303.304585]
    efivarfs_file_write+0xd0/0x1a4 [ 303.305148] vfs_write+0xc4/0x2e4 [ 303.305601] ksys_write+0x70/0x104 [
    303.306073] __arm64_sys_write+0x1c/0x28 [ 303.306622] invoke_syscall+0x48/0x114 [ 303.307156]
    el0_svc_common.constprop.0+0x44/0xec [ 303.307803] do_el0_svc+0x38/0x98 [ 303.308268] el0_svc+0x2c/0x84 [
    303.308702] el0t_64_sync_handler+0xf4/0x120 [ 303.309293] el0t_64_sync+0x190/0x194 [ 303.309794] Code:
    ???????? ???????? ???????? ???????? (????????) [ 303.310612] ---[ end trace 0000000000000000 ]--- Fix this
    by adding a .reconfigure() function to the fs operations which we can use to check the requested flags and
    deny anything that's not RO if the firmware doesn't implement SetVariable at runtime.(CVE-2023-52463)

    In the Linux kernel, the following vulnerability has been resolved: bpf: fix check for attempt to corrupt
    spilled pointer When register is spilled onto a stack as a 1/2/4-byte register, we set
    slot_type[BPF_REG_SIZE - 1] (plus potentially few more below it, depending on actual spill size). So to
    check if some stack slot has spilled register we need to consult slot_type[7], not slot_type[0]. To avoid
    the need to remember and double-check this in the future, just use is_spilled_reg()
    helper.(CVE-2023-52462)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-tcp: Fix a kernel panic when
    host sends an invalid H2C PDU length If the host sends an H2CData command with an invalid DATAL, the
    kernel may crash in nvmet_tcp_build_pdu_iovec(). Unable to handle kernel NULL pointer dereference at
    virtual address 0000000000000000 lr : nvmet_tcp_io_work+0x6ac/0x718 [nvmet_tcp] Call trace:
    process_one_work+0x174/0x3c8 worker_thread+0x2d0/0x3e8 kthread+0x104/0x110 Fix the bug by raising a fatal
    error if DATAL isn't coherent with the packet size. Also, the PDU length should never exceed the
    MAXH2CDATA parameter which has been communicated to the host in nvmet_tcp_handle_icreq().(CVE-2023-52454)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix accesses to uninit stack
    slots Privileged programs are supposed to be able to read uninitialized stack memory (ever since
    6715df8d5) but, before this patch, these accesses were permitted inconsistently. In particular, accesses
    were permitted above state-allocated_stack, but not below it. In other words, if the stack was already
    'large enough', the access was permitted, but otherwise the access was rejected instead of being allowed
    to 'grow the stack'. This undesired rejection was happening in two places: - in
    check_stack_slot_within_bounds() - in check_stack_range_initialized() This patch arranges for these
    accesses to be permitted. A bunch of tests that were relying on the old rejection had to change; all of
    them were changed to add also run unprivileged, in which case the old behavior persists. One tests
    couldn't be updated - global_func16 - because it can't run unprivileged for other reasons. This patch also
    fixes the tracking of the stack size for variable-offset reads. This second fix is bundled in the same
    commit as the first one because they're inter-related. Before this patch, writes to the stack using
    registers containing a variable offset (as opposed to registers with fixed, known values) were not
    properly contributing to the function's needed stack size. As a result, it was possible for a program to
    verify, but then to attempt to read out-of-bounds data at runtime because a too small stack had been
    allocated for it. Each function tracks the size of the stack it needs in bpf_subprog_info.stack_depth,
    which is maintained by update_stack_depth(). For regular memory accesses, check_mem_access() was calling
    update_state_depth() but it was passing in only the fixed part of the offset register, ignoring the
    variable offset. This was incorrect; the minimum possible value of that register should be used instead.
    This tracking is now fixed by centralizing the tracking of stack size in grow_stack_state(), and by
    lifting the calls to grow_stack_state() to check_stack_access_within_bounds() as suggested by Andrii. The
    code is now simpler and more convincingly tracks the correct maximum stack size.
    check_stack_range_initialized() can now rely on enough stack having been allocated for the access; this
    helps with the fix for the first issue. A few tests were changed to also check the stack depth
    computation. The one that fails without this patch is
    verifier_var_off:stack_write_priv_vs_unpriv.(CVE-2023-52452)

    In the Linux kernel, the following vulnerability has been resolved: powerpc/pseries/memhp: Fix access
    beyond end of drmem array dlpar_memory_remove_by_index() may access beyond the bounds of the drmem lmb
    array when the LMB lookup fails to match an entry with the given DRC index. When the search fails, the
    cursor is left pointing to drmem_info-lmbs[drmem_info-n_lmbs], which is one element past the last
    valid entry in the array. The debug message at the end of the function then dereferences this pointer:
    pr_debug('Failed to hot-remove memory at %llx\n', lmb-base_addr); This was found by inspection and
    confirmed with KASAN: pseries-hotplug-mem: Attempting to hot-remove LMB, drc index 1234
    ================================================================== BUG: KASAN: slab-out-of-bounds in
    dlpar_memory+0x298/0x1658 Read of size 8 at addr c000000364e97fd0 by task bash/949
    dump_stack_lvl+0xa4/0xfc (unreliable) print_report+0x214/0x63c kasan_report+0x140/0x2e0
    __asan_load8+0xa8/0xe0 dlpar_memory+0x298/0x1658 handle_dlpar_errorlog+0x130/0x1d0 dlpar_store+0x18c/0x3e0
    kobj_attr_store+0x68/0xa0 sysfs_kf_write+0xc4/0x110 kernfs_fop_write_iter+0x26c/0x390
    vfs_write+0x2d4/0x4e0 ksys_write+0xac/0x1a0 system_call_exception+0x268/0x530
    system_call_vectored_common+0x15c/0x2ec Allocated by task 1: kasan_save_stack+0x48/0x80
    kasan_set_track+0x34/0x50 kasan_save_alloc_info+0x34/0x50 __kasan_kmalloc+0xd0/0x120 __kmalloc+0x8c/0x320
    kmalloc_array.constprop.0+0x48/0x5c drmem_init+0x2a0/0x41c do_one_initcall+0xe0/0x5c0
    kernel_init_freeable+0x4ec/0x5a0 kernel_init+0x30/0x1e0 ret_from_kernel_user_thread+0x14/0x1c The buggy
    address belongs to the object at c000000364e80000 which belongs to the cache kmalloc-128k of size 131072
    The buggy address is located 0 bytes to the right of allocated 98256-byte region [c000000364e80000,
    c000000364e97fd0) ================================================================== pseries-hotplug-mem:
    Failed to hot-remove memory at 0 Log failed lookups with a separate message and dereference the cursor
    only when it points to a valid entry.(CVE-2023-52451)

    In the Linux kernel, the following vulnerability has been resolved: gfs2: Fix kernel NULL pointer
    dereference in gfs2_rgrp_dump Syzkaller has reported a NULL pointer dereference when accessing rgd-
    rd_rgl in gfs2_rgrp_dump(). This can happen when creating rgd-rd_gl fails in read_rindex_entry().
    Add a NULL pointer check in gfs2_rgrp_dump() to prevent that.(CVE-2023-52448)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Defer the free of inner map when
    necessary When updating or deleting an inner map in map array or map htab, the map may still be accessed
    by non-sleepable program or sleepable program. However bpf_map_fd_put_ptr() decreases the ref-counter of
    the inner map directly through bpf_map_put(), if the ref-counter is the last one (which is true for most
    cases), the inner map will be freed by ops-map_free() in a kworker. But for now, most .map_free()
    callbacks don't use synchronize_rcu() or its variants to wait for the elapse of a RCU grace period, so
    after the invocation of ops-map_free completes, the bpf program which is accessing the inner map may
    incur use-after-free problem. Fix the free of inner map by invoking bpf_map_free_deferred() after both one
    RCU grace period and one tasks trace RCU grace period if the inner map has been removed from the outer map
    before. The deferment is accomplished by using call_rcu() or call_rcu_tasks_trace() when releasing the
    last ref-counter of bpf map. The newly-added rcu_head field in bpf_map shares the same storage space with
    work field to reduce the size of bpf_map.(CVE-2023-52447)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on
    context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func
    function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that
    might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check
    before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

    In the Linux kernel, the following vulnerability has been resolved: apparmor: avoid crash when parsed
    profile name is empty When processing a packed profile in unpack_profile() described like 'profile
    :ns::samba-dcerpcd /usr/lib*/samba/{,samba/}samba-dcerpcd {...}' a string ':samba-dcerpcd' is unpacked as
    a fully-qualified name and then passed to aa_splitn_fqname(). aa_splitn_fqname() treats ':samba-dcerpcd'
    as only containing a namespace. Thus it returns NULL for tmpname, meanwhile tmpns is non-NULL. Later
    aa_alloc_profile() crashes as the new profile name is NULL now. general protection fault, probably for
    non-canonical address 0xdffffc0000000000: 0000 [#1] PREEMPT SMP KASAN NOPTI KASAN: null-ptr-deref in range
    [0x0000000000000000-0x0000000000000007] CPU: 6 PID: 1657 Comm: apparmor_parser Not tainted 6.7.0-rc2-dirty
    #16 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.16.2-3-gd478f380-rebuilt.opensuse.org 04/01/2014 RIP: 0010:strlen+0x1e/0xa0 Call Trace: TASK ?
    strlen+0x1e/0xa0 aa_policy_init+0x1bb/0x230 aa_alloc_profile+0xb1/0x480 unpack_profile+0x3bc/0x4960
    aa_unpack+0x309/0x15e0 aa_replace_profiles+0x213/0x33c0 policy_update+0x261/0x370
    profile_replace+0x20e/0x2a0 vfs_write+0x2af/0xe00 ksys_write+0x126/0x250 do_syscall_64+0x46/0xf0
    entry_SYSCALL_64_after_hwframe+0x6e/0x76 /TASK ---[ end trace 0000000000000000 ]--- RIP:
    0010:strlen+0x1e/0xa0 It seems such behaviour of aa_splitn_fqname() is expected and checked in other
    places where it is called (e.g. aa_remove_profiles). Well, there is an explicit comment 'a ns name without
    a following profile is allowed' inside. AFAICS, nothing can prevent unpacked 'name' to be in form like
    ':samba-dcerpcd' - it is passed from userspace. Deny the whole profile set replacement in such case and
    inform user with EPROTO and an explaining message. Found by Linux Verification Center
    (linuxtesting.org).(CVE-2023-52443)

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

    In the Linux kernel, the following vulnerability has been resolved: binder: fix use-after-free in
    shinker's callback The mmap read lock is used during the shrinker's callback, which means that using
    alloc-vma pointer isn't safe as it can race with munmap(). As of commit dd2283f2605e ('mm: mmap: zap
    pages with read mmap_sem in munmap') the mmap lock is downgraded after the vma has been isolated. I was
    able to reproduce this issue by manually adding some delays and triggering page reclaiming through the
    shrinker's debug sysfs. The following KASAN report confirms the UAF:
    ================================================================== BUG: KASAN: slab-use-after-free in
    zap_page_range_single+0x470/0x4b8 Read of size 8 at addr ffff356ed50e50f0 by task bash/478 CPU: 1 PID: 478
    Comm: bash Not tainted 6.6.0-rc5-00055-g1c8b86a3799f-dirty #70 Hardware name: linux,dummy-virt (DT) Call
    trace: zap_page_range_single+0x470/0x4b8 binder_alloc_free_page+0x608/0xadc
    __list_lru_walk_one+0x130/0x3b0 list_lru_walk_node+0xc4/0x22c binder_shrink_scan+0x108/0x1dc
    shrinker_debugfs_scan_write+0x2b4/0x500 full_proxy_write+0xd4/0x140 vfs_write+0x1ac/0x758
    ksys_write+0xf0/0x1dc __arm64_sys_write+0x6c/0x9c Allocated by task 492: kmem_cache_alloc+0x130/0x368
    vm_area_alloc+0x2c/0x190 mmap_region+0x258/0x18bc do_mmap+0x694/0xa60 vm_mmap_pgoff+0x170/0x29c
    ksys_mmap_pgoff+0x290/0x3a0 __arm64_sys_mmap+0xcc/0x144 Freed by task 491: kmem_cache_free+0x17c/0x3c8
    vm_area_free_rcu_cb+0x74/0x98 rcu_core+0xa38/0x26d4 rcu_core_si+0x10/0x1c __do_softirq+0x2fc/0xd24 Last
    potentially related work creation: __call_rcu_common.constprop.0+0x6c/0xba0 call_rcu+0x10/0x1c
    vm_area_free+0x18/0x24 remove_vma+0xe4/0x118 do_vmi_align_munmap.isra.0+0x718/0xb5c
    do_vmi_munmap+0xdc/0x1fc __vm_munmap+0x10c/0x278 __arm64_sys_munmap+0x58/0x7c Fix this issue by performing
    instead a vma_lookup() which will fail to find the vma that was isolated before the mmap lock downgrade.
    Note that this option has better performance than upgrading to a mmap write lock which would increase
    contention. Plus, mmap_write_trylock() has been recently removed anyway.(CVE-2023-52438)

    A flaw was found in the Linux kernels net/core/skbuff.c subsystem. The GSO_BY_FRAGS is a forbidden
    value and allows the following computation in skb_segment() to reach it. The : mss = mss * partial_segs
    and many initial mss values can lead to a bad final result. Limit the segmentation so that the new mss
    value is smaller than GSO_BY_FRAGS.(CVE-2023-52435)

    A flaw was found in the smb client in the Linux kernel. A potential out-of-bounds error was seen in the
    smb2_parse_contexts() function. Validate offsets and lengths before dereferencing create contexts in
    smb2_parse_contexts().(CVE-2023-52434)

    A null pointer dereference flaw was found in the hugetlbfs_fill_super function in the Linux kernel
    hugetlbfs (HugeTLB pages) functionality. This issue may allow a local user to crash the system or
    potentially escalate their privileges on the system.(CVE-2024-0841)

    In the Linux kernel, the following vulnerability has been resolved: udp: skip L4 aggregation for UDP
    tunnel packets If NETIF_F_GRO_FRAGLIST or NETIF_F_GRO_UDP_FWD are enabled, and there are UDP tunnels
    available in the system, udp_gro_receive() could end-up doing L4 aggregation (either SKB_GSO_UDP_L4 or
    SKB_GSO_FRAGLIST) at the outer UDP tunnel level for packets effectively carrying and UDP tunnel header.
    That could cause inner protocol corruption. If e.g. the relevant packets carry a vxlan header, different
    vxlan ids will be ignored/ aggregated to the same GSO packet. Inner headers will be ignored, too, so that
    e.g. TCP over vxlan push packets will be held in the GRO engine till the next flush, etc. Just skip the
    SKB_GSO_UDP_L4 and SKB_GSO_FRAGLIST code path if the current packet could land in a UDP tunnel, and let
    udp_gro_receive() do GRO via udp_sk(sk)-gro_receive. The check implemented in this patch is broader
    than what is strictly needed, as the existing UDP tunnel could be e.g. configured on top of a different
    device: we could end-up skipping GRO at-all for some packets. Anyhow, that is a very thin corner case and
    covering it will add quite a bit of complexity. v1 - v2: - hopefully clarify the commit
    message(CVE-2021-47036)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1800
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d7400c9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h1209.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1209.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1209.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1209.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1209.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1209.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
