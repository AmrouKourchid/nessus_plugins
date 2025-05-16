#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(211829);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id(
    "CVE-2024-38564",
    "CVE-2024-40914",
    "CVE-2024-43898",
    "CVE-2024-45009",
    "CVE-2024-45010",
    "CVE-2024-45020",
    "CVE-2024-46695",
    "CVE-2024-46711",
    "CVE-2024-46828",
    "CVE-2024-47675",
    "CVE-2024-47685",
    "CVE-2024-47700",
    "CVE-2024-47703",
    "CVE-2024-47745",
    "CVE-2024-49888",
    "CVE-2024-49948",
    "CVE-2024-49968",
    "CVE-2024-50014",
    "CVE-2024-50015",
    "CVE-2024-50018",
    "CVE-2024-50033",
    "CVE-2024-50093",
    "CVE-2024-50099",
    "CVE-2024-50110",
    "CVE-2024-50127",
    "CVE-2024-50130",
    "CVE-2024-50142",
    "CVE-2024-50154",
    "CVE-2024-50186",
    "CVE-2024-50191",
    "CVE-2024-50262"
  );

  script_name(english:"CentOS 9 : kernel-5.14.0-533.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for bpftool.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
kernel-5.14.0-533.el9 build changelog.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Add BPF_PROG_TYPE_CGROUP_SKB
    attach type enforcement in BPF_LINK_CREATE bpf_prog_attach uses attach_type_to_prog_type to enforce proper
    attach type for BPF_PROG_TYPE_CGROUP_SKB. link_create uses bpf_prog_get and relies on
    bpf_prog_attach_check_attach_type to properly verify prog_type <> attach_type association. Add missing
    attach_type enforcement for the link_create case. Otherwise, it's currently possible to attach cgroup_skb
    prog types to other cgroup hooks. (CVE-2024-38564)

  - In the Linux kernel, the following vulnerability has been resolved: mm/huge_memory: don't unpoison
    huge_zero_folio When I did memory failure tests recently, below panic occurs: kernel BUG at
    include/linux/mm.h:1135! invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 9 PID: 137 Comm: kswapd1 Not
    tainted 6.9.0-rc4-00491-gd5ce28f156fe-dirty #14 RIP: 0010:shrink_huge_zero_page_scan+0x168/0x1a0 RSP:
    0018:ffff9933c6c57bd0 EFLAGS: 00000246 RAX: 000000000000003e RBX: 0000000000000000 RCX: ffff88f61fc5c9c8
    RDX: 0000000000000000 RSI: 0000000000000027 RDI: ffff88f61fc5c9c0 RBP: ffffcd7c446b0000 R08:
    ffffffff9a9405f0 R09: 0000000000005492 R10: 00000000000030ea R11: ffffffff9a9405f0 R12: 0000000000000000
    R13: 0000000000000000 R14: 0000000000000000 R15: ffff88e703c4ac00 FS: 0000000000000000(0000)
    GS:ffff88f61fc40000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    000055f4da6e9878 CR3: 0000000c71048000 CR4: 00000000000006f0 Call Trace: <TASK> do_shrink_slab+0x14f/0x6a0
    shrink_slab+0xca/0x8c0 shrink_node+0x2d0/0x7d0 balance_pgdat+0x33a/0x720 kswapd+0x1f3/0x410
    kthread+0xd5/0x100 ret_from_fork+0x2f/0x50 ret_from_fork_asm+0x1a/0x30 </TASK> Modules linked in:
    mce_inject hwpoison_inject ---[ end trace 0000000000000000 ]--- RIP:
    0010:shrink_huge_zero_page_scan+0x168/0x1a0 RSP: 0018:ffff9933c6c57bd0 EFLAGS: 00000246 RAX:
    000000000000003e RBX: 0000000000000000 RCX: ffff88f61fc5c9c8 RDX: 0000000000000000 RSI: 0000000000000027
    RDI: ffff88f61fc5c9c0 RBP: ffffcd7c446b0000 R08: ffffffff9a9405f0 R09: 0000000000005492 R10:
    00000000000030ea R11: ffffffff9a9405f0 R12: 0000000000000000 R13: 0000000000000000 R14: 0000000000000000
    R15: ffff88e703c4ac00 FS: 0000000000000000(0000) GS:ffff88f61fc40000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055f4da6e9878 CR3: 0000000c71048000 CR4: 00000000000006f0
    The root cause is that HWPoison flag will be set for huge_zero_folio without increasing the folio refcnt.
    But then unpoison_memory() will decrease the folio refcnt unexpectedly as it appears like a successfully
    hwpoisoned folio leading to VM_BUG_ON_PAGE(page_ref_count(page) == 0) when releasing huge_zero_folio. Skip
    unpoisoning huge_zero_folio in unpoison_memory() to fix this issue. We're not prepared to unpoison
    huge_zero_folio yet. (CVE-2024-40914)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: sanity check for NULL pointer
    after ext4_force_shutdown Test case: 2 threads write short inline data to a file. In ext4_page_mkwrite the
    resulting inline data is converted. Handling ext4_grp_locked_error with description block bitmap and bg
    descriptor inconsistent: X vs Y free clusters calls ext4_force_shutdown. The conversion clears
    EXT4_STATE_MAY_INLINE_DATA but fails for ext4_destroy_inline_data_nolock and ext4_mark_iloc_dirty due to
    ext4_forced_shutdown. The restoration of inline data fails for the same reason not setting
    EXT4_STATE_MAY_INLINE_DATA. Without the flag set a regular process path in ext4_da_write_end follows
    trying to dereference page folio private pointer that has not been set. The fix calls early return with
    -EIO error shall the pointer to private be NULL. Sample crash report: Unable to handle kernel paging
    request at virtual address dfff800000000004 KASAN: null-ptr-deref in range
    [0x0000000000000020-0x0000000000000027] Mem abort info: ESR = 0x0000000096000005 EC = 0x25: DABT (current
    EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1 translation fault Data abort
    info: ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0,
    Overlay = 0, DirtyBit = 0, Xs = 0 [dfff800000000004] address between user and kernel address ranges
    Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP Modules linked in: CPU: 1 PID: 20274 Comm: syz-
    executor185 Not tainted 6.9.0-rc7-syzkaller-gfda5695d692c #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 03/27/2024 pstate: 80400005 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS
    BTYPE=--) pc : __block_commit_write+0x64/0x2b0 fs/buffer.c:2167 lr : __block_commit_write+0x3c/0x2b0
    fs/buffer.c:2160 sp : ffff8000a1957600 x29: ffff8000a1957610 x28: dfff800000000000 x27: ffff0000e30e34b0
    x26: 0000000000000000 x25: dfff800000000000 x24: dfff800000000000 x23: fffffdffc397c9e0 x22:
    0000000000000020 x21: 0000000000000020 x20: 0000000000000040 x19: fffffdffc397c9c0 x18: 1fffe000367bd196
    x17: ffff80008eead000 x16: ffff80008ae89e3c x15: 00000000200000c0 x14: 1fffe0001cbe4e04 x13:
    0000000000000000 x12: 0000000000000000 x11: 0000000000000001 x10: 0000000000ff0100 x9 : 0000000000000000
    x8 : 0000000000000004 x7 : 0000000000000000 x6 : 0000000000000000 x5 : fffffdffc397c9c0 x4 :
    0000000000000020 x3 : 0000000000000020 x2 : 0000000000000040 x1 : 0000000000000020 x0 : fffffdffc397c9c0
    Call trace: __block_commit_write+0x64/0x2b0 fs/buffer.c:2167 block_write_end+0xb4/0x104 fs/buffer.c:2253
    ext4_da_do_write_end fs/ext4/inode.c:2955 [inline] ext4_da_write_end+0x2c4/0xa40 fs/ext4/inode.c:3028
    generic_perform_write+0x394/0x588 mm/filemap.c:3985 ext4_buffered_write_iter+0x2c0/0x4ec
    fs/ext4/file.c:299 ext4_file_write_iter+0x188/0x1780 call_write_iter include/linux/fs.h:2110 [inline]
    new_sync_write fs/read_write.c:497 [inline] vfs_write+0x968/0xc3c fs/read_write.c:590
    ksys_write+0x15c/0x26c fs/read_write.c:643 __do_sys_write fs/read_write.c:655 [inline] __se_sys_write
    fs/read_write.c:652 [inline] __arm64_sys_write+0x7c/0x90 fs/read_write.c:652 __invoke_syscall
    arch/arm64/kernel/syscall.c:34 [inline] invoke_syscall+0x98/0x2b8 arch/arm64/kernel/syscall.c:48
    el0_svc_common+0x130/0x23c arch/arm64/kernel/syscall.c:133 do_el0_svc+0x48/0x58
    arch/arm64/kernel/syscall.c:152 el0_svc+0x54/0x168 arch/arm64/kernel/entry-common.c:712
    el0t_64_sync_handler+0x84/0xfc arch/arm64/kernel/entry-common.c:730 el0t_64_sync+0x190/0x194
    arch/arm64/kernel/entry.S:598 Code: 97f85911 f94002da 91008356 d343fec8 (38796908) ---[ end trace
    0000000000000000 ]--- ---------------- Code disassembly (best guess): 0: 97f85911 bl 0xffffffffffe16444 4:
    f94002da ldr x26, [x22] 8: 91008356 add x22, x26, #0x20 c: d343fec8 lsr x8, x22, #3 * 10: 38796908 ldrb
    w8, [x8, x25] <-- trapping instruction (CVE-2024-43898)

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: pm: only decrement
    add_addr_accepted for MPJ req Adding the following warning ... WARN_ON_ONCE(msk->pm.add_addr_accepted ==
    0) ... before decrementing the add_addr_accepted counter helped to find a bug when running the remove
    single subflow subtest from the mptcp_join.sh selftest. Removing a 'subflow' endpoint will first trigger
    a RM_ADDR, then the subflow closure. Before this patch, and upon the reception of the RM_ADDR, the other
    peer will then try to decrement this add_addr_accepted. That's not correct because the attached subflows
    have not been created upon the reception of an ADD_ADDR. A way to solve that is to decrement the counter
    only if the attached subflow was an MP_JOIN to a remote id that was not 0, and initiated by the host
    receiving the RM_ADDR. (CVE-2024-45009)

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: pm: only mark 'subflow' endp as
    available Adding the following warning ... WARN_ON_ONCE(msk->pm.local_addr_used == 0) ... before
    decrementing the local_addr_used counter helped to find a bug when running the remove single address
    subtest from the mptcp_join.sh selftests. Removing a 'signal' endpoint will trigger the removal of all
    subflows linked to this endpoint via mptcp_pm_nl_rm_addr_or_subflow() with rm_type == MPTCP_MIB_RMSUBFLOW.
    This will decrement the local_addr_used counter, which is wrong in this case because this counter is
    linked to 'subflow' endpoints, and here it is a 'signal' endpoint that is being removed. Now, the counter
    is decremented, only if the ID is being used outside of mptcp_pm_nl_rm_addr_or_subflow(), only for
    'subflow' endpoints, and if the ID is not 0 -- local_addr_used is not taking into account these ones. This
    marking of the ID as being available, and the decrement is done no matter if a subflow using this ID is
    currently available, because the subflow could have been closed before. (CVE-2024-45010)

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix a kernel verifier crash in
    stacksafe() Daniel Hodges reported a kernel verifier crash when playing with sched-ext. Further
    investigation shows that the crash is due to invalid memory access in stacksafe(). More specifically, it
    is the following code: if (exact != NOT_EXACT && old->stack[spi].slot_type[i % BPF_REG_SIZE] !=
    cur->stack[spi].slot_type[i % BPF_REG_SIZE]) return false; The 'i' iterates old->allocated_stack. If
    cur->allocated_stack < old->allocated_stack the out-of-bound access will happen. To fix the issue add 'i
    >= cur->allocated_stack' check such that if the condition is true, stacksafe() should fail. Otherwise,
    cur->stack[spi].slot_type[i % BPF_REG_SIZE] memory access is legal. (CVE-2024-45020)

  - In the Linux kernel, the following vulnerability has been resolved: selinux,smack: don't bypass
    permissions check in inode_setsecctx hook Marek Gresko reports that the root user on an NFS client is able
    to change the security labels on files on an NFS filesystem that is exported with root squashing enabled.
    The end of the kerneldoc comment for __vfs_setxattr_noperm() states: * This function requires the caller
    to lock the inode's i_mutex before it * is executed. It also assumes that the caller will make the
    appropriate * permission checks. nfsd_setattr() does do permissions checking via fh_verify() and
    nfsd_permission(), but those don't do all the same permissions checks that are done by
    security_inode_setxattr() and its related LSM hooks do. Since nfsd_setattr() is the only consumer of
    security_inode_setsecctx(), simplest solution appears to be to replace the call to __vfs_setxattr_noperm()
    with a call to __vfs_setxattr_locked(). This fixes the above issue and has the added benefit of causing
    nfsd to recall conflicting delegations on a file when a client tries to change its security label.
    (CVE-2024-46695)

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: pm: fix ID 0 endp usage after
    multiple re-creations 'local_addr_used' and 'add_addr_accepted' are decremented for addresses not related
    to the initial subflow (ID0), because the source and destination addresses of the initial subflows are
    known from the beginning: they don't count as additional local address being used or ADD_ADDR being
    accepted. It is then required not to increment them when the entrypoint used by the initial subflow is
    removed and re-added during a connection. Without this modification, this entrypoint cannot be removed and
    re-added more than once. (CVE-2024-46711)

  - In the Linux kernel, the following vulnerability has been resolved: sched: sch_cake: fix bulk flow
    accounting logic for host fairness In sch_cake, we keep track of the count of active bulk flows per host,
    when running in dst/src host fairness mode, which is used as the round-robin weight when iterating through
    flows. The count of active bulk flows is updated whenever a flow changes state. This has a peculiar
    interaction with the hash collision handling: when a hash collision occurs (after the set-associative
    hashing), the state of the hash bucket is simply updated to match the new packet that collided, and if
    host fairness is enabled, that also means assigning new per-host state to the flow. For this reason, the
    bulk flow counters of the host(s) assigned to the flow are decremented, before new state is assigned (and
    the counters, which may not belong to the same host anymore, are incremented again). Back when this code
    was introduced, the host fairness mode was always enabled, so the decrement was unconditional. When the
    configuration flags were introduced the *increment* was made conditional, but the *decrement* was not.
    Which of course can lead to a spurious decrement (and associated wrap-around to U16_MAX). AFAICT, when
    host fairness is disabled, the decrement and wrap-around happens as soon as a hash collision occurs (which
    is not that common in itself, due to the set-associative hashing). However, in most cases this is
    harmless, as the value is only used when host fairness mode is enabled. So in order to trigger an array
    overflow, sch_cake has to first be configured with host fairness disabled, and while running in this mode,
    a hash collision has to occur to cause the overflow. Then, the qdisc has to be reconfigured to enable host
    fairness, which leads to the array out-of-bounds because the wrapped-around value is retained and used as
    an array index. It seems that syzbot managed to trigger this, which is quite impressive in its own right.
    This patch fixes the issue by introducing the same conditional check on decrement as is used on increment.
    The original bug predates the upstreaming of cake, but the commit listed in the Fixes tag touched that
    code, meaning that this patch won't apply before that. (CVE-2024-46828)

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix use-after-free in
    bpf_uprobe_multi_link_attach() If bpf_link_prime() fails, bpf_uprobe_multi_link_attach() goes to the
    error_free label and frees the array of bpf_uprobe's without calling bpf_uprobe_unregister(). This leaks
    bpf_uprobe->uprobe and worse, this frees bpf_uprobe->consumer without removing it from the
    uprobe->consumers list. (CVE-2024-47675)

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_reject_ipv6: fix
    nf_reject_ip6_tcphdr_put() syzbot reported that nf_reject_ip6_tcphdr_put() was possibly sending garbage on
    the four reserved tcp bits (th->res1) Use skb_put_zero() to clear the whole TCP header, as done in
    nf_reject_ip_tcphdr_put() BUG: KMSAN: uninit-value in nf_reject_ip6_tcphdr_put+0x688/0x6c0
    net/ipv6/netfilter/nf_reject_ipv6.c:255 nf_reject_ip6_tcphdr_put+0x688/0x6c0
    net/ipv6/netfilter/nf_reject_ipv6.c:255 nf_send_reset6+0xd84/0x15b0
    net/ipv6/netfilter/nf_reject_ipv6.c:344 nft_reject_inet_eval+0x3c1/0x880
    net/netfilter/nft_reject_inet.c:48 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline]
    nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288 nft_do_chain_inet+0x41a/0x4f0
    net/netfilter/nft_chain_filter.c:161 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline]
    nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook include/linux/netfilter.h:269 [inline] NF_HOOK
    include/linux/netfilter.h:312 [inline] ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310
    __netif_receive_skb_one_core net/core/dev.c:5661 [inline] __netif_receive_skb+0x1da/0xa00
    net/core/dev.c:5775 process_backlog+0x4ad/0xa50 net/core/dev.c:6108 __napi_poll+0xe7/0x980
    net/core/dev.c:6772 napi_poll net/core/dev.c:6841 [inline] net_rx_action+0xa5a/0x19b0 net/core/dev.c:6963
    handle_softirqs+0x1ce/0x800 kernel/softirq.c:554 __do_softirq+0x14/0x1a kernel/softirq.c:588
    do_softirq+0x9a/0x100 kernel/softirq.c:455 __local_bh_enable_ip+0x9f/0xb0 kernel/softirq.c:382
    local_bh_enable include/linux/bottom_half.h:33 [inline] rcu_read_unlock_bh include/linux/rcupdate.h:908
    [inline] __dev_queue_xmit+0x2692/0x5610 net/core/dev.c:4450 dev_queue_xmit include/linux/netdevice.h:3105
    [inline] neigh_resolve_output+0x9ca/0xae0 net/core/neighbour.c:1565 neigh_output
    include/net/neighbour.h:542 [inline] ip6_finish_output2+0x2347/0x2ba0 net/ipv6/ip6_output.c:141
    __ip6_finish_output net/ipv6/ip6_output.c:215 [inline] ip6_finish_output+0xbb8/0x14b0
    net/ipv6/ip6_output.c:226 NF_HOOK_COND include/linux/netfilter.h:303 [inline] ip6_output+0x356/0x620
    net/ipv6/ip6_output.c:247 dst_output include/net/dst.h:450 [inline] NF_HOOK include/linux/netfilter.h:314
    [inline] ip6_xmit+0x1ba6/0x25d0 net/ipv6/ip6_output.c:366 inet6_csk_xmit+0x442/0x530
    net/ipv6/inet6_connection_sock.c:135 __tcp_transmit_skb+0x3b07/0x4880 net/ipv4/tcp_output.c:1466
    tcp_transmit_skb net/ipv4/tcp_output.c:1484 [inline] tcp_connect+0x35b6/0x7130 net/ipv4/tcp_output.c:4143
    tcp_v6_connect+0x1bcc/0x1e40 net/ipv6/tcp_ipv6.c:333 __inet_stream_connect+0x2ef/0x1730
    net/ipv4/af_inet.c:679 inet_stream_connect+0x6a/0xd0 net/ipv4/af_inet.c:750 __sys_connect_file
    net/socket.c:2061 [inline] __sys_connect+0x606/0x690 net/socket.c:2078 __do_sys_connect net/socket.c:2088
    [inline] __se_sys_connect net/socket.c:2085 [inline] __x64_sys_connect+0x91/0xe0 net/socket.c:2085
    x64_sys_call+0x27a5/0x3ba0 arch/x86/include/generated/asm/syscalls_64.h:43 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f Uninit was stored to memory at:
    nf_reject_ip6_tcphdr_put+0x60c/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:249 nf_send_reset6+0xd84/0x15b0
    net/ipv6/netfilter/nf_reject_ipv6.c:344 nft_reject_inet_eval+0x3c1/0x880
    net/netfilter/nft_reject_inet.c:48 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline]
    nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288 nft_do_chain_inet+0x41a/0x4f0
    net/netfilter/nft_chain_filter.c:161 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline]
    nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook include/linux/netfilter.h:269 [inline] NF_HOOK
    include/linux/netfilter.h:312 [inline] ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310
    __netif_receive_skb_one_core ---truncated--- (CVE-2024-47685)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: check stripe size compatibility
    on remount as well We disable stripe size in __ext4_fill_super if it is not a multiple of the cluster
    ratio however this check is missed when trying to remount. This can leave us with cases where stripe <
    cluster_ratio after remount:set making EXT4_B2C(sbi->s_stripe) become 0 that can cause some unforeseen
    bugs like divide by 0. Fix that by adding the check in remount path as well. (CVE-2024-47700)

  - In the Linux kernel, the following vulnerability has been resolved: bpf, lsm: Add check for BPF LSM return
    value A bpf prog returning a positive number attached to file_alloc_security hook makes kernel panic. This
    happens because file system can not filter out the positive number returned by the LSM prog using IS_ERR,
    and misinterprets this positive number as a file pointer. Given that hook file_alloc_security never
    returned positive number before the introduction of BPF LSM, and other BPF LSM hooks may encounter similar
    issues, this patch adds LSM return value check in verifier, to ensure no unexpected value is returned.
    (CVE-2024-47703)

  - In the Linux kernel, the following vulnerability has been resolved: mm: call the security_mmap_file() LSM
    hook in remap_file_pages() The remap_file_pages syscall handler calls do_mmap() directly, which doesn't
    contain the LSM security check. And if the process has called personality(READ_IMPLIES_EXEC) before and
    remap_file_pages() is called for RW pages, this will actually result in remapping the pages to RWX,
    bypassing a W^X policy enforced by SELinux. So we should check prot by security_mmap_file LSM hook in the
    remap_file_pages syscall handler before do_mmap() is called. Otherwise, it potentially permits an attacker
    to bypass a W^X policy enforced by SELinux. The bypass is similar to CVE-2016-10044, which bypass the same
    thing via AIO and can be found in [1]. The PoC: $ cat > test.c int main(void) { size_t pagesz =
    sysconf(_SC_PAGE_SIZE); int mfd = syscall(SYS_memfd_create, test, 0); const char *buf = mmap(NULL, 4 *
    pagesz, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0); unsigned int old = syscall(SYS_personality,
    0xffffffff); syscall(SYS_personality, READ_IMPLIES_EXEC | old); syscall(SYS_remap_file_pages, buf, pagesz,
    0, 2, 0); syscall(SYS_personality, old); // show the RWX page exists even if W^X policy is enforced int fd
    = open(/proc/self/maps, O_RDONLY); unsigned char buf2[1024]; while (1) { int ret = read(fd, buf2, 1024);
    if (ret <= 0) break; write(1, buf2, ret); } close(fd); } $ gcc test.c -o test $ ./test | grep rwx
    7f1836c34000-7f1836c35000 rwxs 00002000 00:01 2050 /memfd:test (deleted) [PM: subject line tweaks]
    (CVE-2024-47745)

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix a sdiv overflow issue Zac
    Ecob reported a problem where a bpf program may cause kernel crash due to the following error: Oops:
    divide error: 0000 [#1] PREEMPT SMP KASAN PTI The failure is due to the below signed divide: LLONG_MIN/-1
    where LLONG_MIN equals to -9,223,372,036,854,775,808. LLONG_MIN/-1 is supposed to give a positive number
    9,223,372,036,854,775,808, but it is impossible since for 64-bit system, the maximum positive number is
    9,223,372,036,854,775,807. On x86_64, LLONG_MIN/-1 will cause a kernel exception. On arm64, the result for
    LLONG_MIN/-1 is LLONG_MIN. Further investigation found all the following sdiv/smod cases may trigger an
    exception when bpf program is running on x86_64 platform: - LLONG_MIN/-1 for 64bit operation - INT_MIN/-1
    for 32bit operation - LLONG_MIN%-1 for 64bit operation - INT_MIN%-1 for 32bit operation where -1 can be an
    immediate or in a register. On arm64, there are no exceptions: - LLONG_MIN/-1 = LLONG_MIN - INT_MIN/-1 =
    INT_MIN - LLONG_MIN%-1 = 0 - INT_MIN%-1 = 0 where -1 can be an immediate or in a register. Insn patching
    is needed to handle the above cases and the patched codes produced results aligned with above arm64
    result. The below are pseudo codes to handle sdiv/smod exceptions including both divisor -1 and divisor 0
    and the divisor is stored in a register. sdiv: tmp = rX tmp += 1 /* [-1, 0] -> [0, 1] if tmp >(unsigned) 1
    goto L2 if tmp == 0 goto L1 rY = 0 L1: rY = -rY; goto L3 L2: rY /= rX L3: smod: tmp = rX tmp += 1 /* [-1,
    0] -> [0, 1] if tmp >(unsigned) 1 goto L1 if tmp == 1 (is64 ? goto L2 : goto L3) rY = 0; goto L2 L1: rY %=
    rX L2: goto L4 // only when !is64 L3: wY = wY // only when !is64 L4: [1]
    https://lore.kernel.org/bpf/tPJLTEh7S_DxFEqAI2Ji5MBSoZVg7_G-
    Py2iaZpAaWtM961fFTWtsnlzwvTbzBzaUzwQAoNATXKUlt0LZOFgnDcIyKCswAnAGdUF3LBrhGQ=@protonmail.com/
    (CVE-2024-49888)

  - In the Linux kernel, the following vulnerability has been resolved: net: add more sanity checks to
    qdisc_pkt_len_init() One path takes care of SKB_GSO_DODGY, assuming skb->len is bigger than hdr_len.
    virtio_net_hdr_to_skb() does not fully dissect TCP headers, it only make sure it is at least 20 bytes. It
    is possible for an user to provide a malicious 'GSO' packet, total length of 80 bytes. - 20 bytes of IPv4
    header - 60 bytes TCP header - a small gso_size like 8 virtio_net_hdr_to_skb() would declare this packet
    as a normal GSO packet, because it would see 40 bytes of payload, bigger than gso_size. We need to make
    detect this case to not underflow qdisc_skb_cb(skb)->pkt_len. (CVE-2024-49948)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: filesystems without casefold
    feature cannot be mounted with siphash When mounting the ext4 filesystem, if the default hash version is
    set to DX_HASH_SIPHASH but the casefold feature is not set, exit the mounting. (CVE-2024-49968)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: fix access to uninitialised lock
    in fc replay path The following kernel trace can be triggered with fstest generic/629 when executed
    against a filesystem with fast-commit feature enabled: INFO: trying to register non-static key. The code
    is fine but needs lockdep annotation, or maybe you didn't initialize this object before use? turning off
    the locking correctness validator. CPU: 0 PID: 866 Comm: mount Not tainted 6.10.0+ #11 Hardware name: QEMU
    Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.2-3-gd478f380-prebuilt.qemu.org 04/01/2014 Call Trace:
    <TASK> dump_stack_lvl+0x66/0x90 register_lock_class+0x759/0x7d0 __lock_acquire+0x85/0x2630 ?
    __find_get_block+0xb4/0x380 lock_acquire+0xd1/0x2d0 ? __ext4_journal_get_write_access+0xd5/0x160
    _raw_spin_lock+0x33/0x40 ? __ext4_journal_get_write_access+0xd5/0x160
    __ext4_journal_get_write_access+0xd5/0x160 ext4_reserve_inode_write+0x61/0xb0
    __ext4_mark_inode_dirty+0x79/0x270 ? ext4_ext_replay_set_iblocks+0x2f8/0x450
    ext4_ext_replay_set_iblocks+0x330/0x450 ext4_fc_replay+0x14c8/0x1540 ? jread+0x88/0x2e0 ?
    rcu_is_watching+0x11/0x40 do_one_pass+0x447/0xd00 jbd2_journal_recover+0x139/0x1b0
    jbd2_journal_load+0x96/0x390 ext4_load_and_init_journal+0x253/0xd40 ext4_fill_super+0x2cc6/0x3180 ... In
    the replay path there's an attempt to lock sbi->s_bdev_wb_lock in function ext4_check_bdev_write_error().
    Unfortunately, at this point this spinlock has not been initialized yet. Moving it's initialization to an
    earlier point in __ext4_fill_super() fixes this splat. (CVE-2024-50014)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: dax: fix overflowing extents
    beyond inode size when partially writing The dax_iomap_rw() does two things in each iteration: map written
    blocks and copy user data to blocks. If the process is killed by user(See signal handling in
    dax_iomap_iter()), the copied data will be returned and added on inode size, which means that the length
    of written extents may exceed the inode size, then fsck will fail. An example is given as: dd
    if=/dev/urandom of=file bs=4M count=1 dax_iomap_rw iomap_iter // round 1 ext4_iomap_begin ext4_iomap_alloc
    // allocate 0~2M extents(written flag) dax_iomap_iter // copy 2M data iomap_iter // round 2
    iomap_iter_advance iter->pos += iter->processed // iter->pos = 2M ext4_iomap_begin ext4_iomap_alloc //
    allocate 2~4M extents(written flag) dax_iomap_iter fatal_signal_pending done = iter->pos - iocb->ki_pos //
    done = 2M ext4_handle_inode_extension ext4_update_inode_size // inode size = 2M fsck reports: Inode 13,
    i_size is 2097152, should be 4194304. Fix? Fix the problem by truncating extents if the written length is
    smaller than expected. (CVE-2024-50015)

  - In the Linux kernel, the following vulnerability has been resolved: net: napi: Prevent overflow of
    napi_defer_hard_irqs In commit 6f8b12d661d0 (net: napi: add hard irqs deferral feature) napi_defer_irqs
    was added to net_device and napi_defer_irqs_count was added to napi_struct, both as type int. This value
    never goes below zero, so there is not reason for it to be a signed int. Change the type for both from int
    to u32, and add an overflow check to sysfs to limit the value to S32_MAX. The limit of S32_MAX was chosen
    because the practical limit before this patch was S32_MAX (anything larger was an overflow) and thus there
    are no behavioral changes introduced. If the extra bit is needed in the future, the limit can be raised.
    Before this patch: $ sudo bash -c 'echo 2147483649 > /sys/class/net/eth4/napi_defer_hard_irqs' $ cat
    /sys/class/net/eth4/napi_defer_hard_irqs -2147483647 After this patch: $ sudo bash -c 'echo 2147483649 >
    /sys/class/net/eth4/napi_defer_hard_irqs' bash: line 0: echo: write error: Numerical result out of range
    Similarly, /sys/class/net/XXXXX/tx_queue_len is defined as unsigned: include/linux/netdevice.h: unsigned
    int tx_queue_len; And has an overflow check: dev_change_tx_queue_len(..., unsigned long new_len): if
    (new_len != (unsigned int)new_len) return -ERANGE; (CVE-2024-50018)

  - In the Linux kernel, the following vulnerability has been resolved: slip: make slhc_remember() more robust
    against malicious packets syzbot found that slhc_remember() was missing checks against malicious packets
    [1]. slhc_remember() only checked the size of the packet was at least 20, which is not good enough. We
    need to make sure the packet includes the IPv4 and TCP header that are supposed to be carried. Add iph and
    th pointers to make the code more readable. [1] BUG: KMSAN: uninit-value in slhc_remember+0x2e8/0x7b0
    drivers/net/slip/slhc.c:666 slhc_remember+0x2e8/0x7b0 drivers/net/slip/slhc.c:666
    ppp_receive_nonmp_frame+0xe45/0x35e0 drivers/net/ppp/ppp_generic.c:2455 ppp_receive_frame
    drivers/net/ppp/ppp_generic.c:2372 [inline] ppp_do_recv+0x65f/0x40d0 drivers/net/ppp/ppp_generic.c:2212
    ppp_input+0x7dc/0xe60 drivers/net/ppp/ppp_generic.c:2327 pppoe_rcv_core+0x1d3/0x720
    drivers/net/ppp/pppoe.c:379 sk_backlog_rcv+0x13b/0x420 include/net/sock.h:1113 __release_sock+0x1da/0x330
    net/core/sock.c:3072 release_sock+0x6b/0x250 net/core/sock.c:3626 pppoe_sendmsg+0x2b8/0xb90
    drivers/net/ppp/pppoe.c:903 sock_sendmsg_nosec net/socket.c:729 [inline] __sock_sendmsg+0x30f/0x380
    net/socket.c:744 ____sys_sendmsg+0x903/0xb60 net/socket.c:2602 ___sys_sendmsg+0x28d/0x3c0
    net/socket.c:2656 __sys_sendmmsg+0x3c1/0x960 net/socket.c:2742 __do_sys_sendmmsg net/socket.c:2771
    [inline] __se_sys_sendmmsg net/socket.c:2768 [inline] __x64_sys_sendmmsg+0xbc/0x120 net/socket.c:2768
    x64_sys_call+0xb6e/0x3ba0 arch/x86/include/generated/asm/syscalls_64.h:308 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f Uninit was created at: slab_post_alloc_hook mm/slub.c:4091
    [inline] slab_alloc_node mm/slub.c:4134 [inline] kmem_cache_alloc_node_noprof+0x6bf/0xb80 mm/slub.c:4186
    kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:587 __alloc_skb+0x363/0x7b0 net/core/skbuff.c:678 alloc_skb
    include/linux/skbuff.h:1322 [inline] sock_wmalloc+0xfe/0x1a0 net/core/sock.c:2732
    pppoe_sendmsg+0x3a7/0xb90 drivers/net/ppp/pppoe.c:867 sock_sendmsg_nosec net/socket.c:729 [inline]
    __sock_sendmsg+0x30f/0x380 net/socket.c:744 ____sys_sendmsg+0x903/0xb60 net/socket.c:2602
    ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2656 __sys_sendmmsg+0x3c1/0x960 net/socket.c:2742
    __do_sys_sendmmsg net/socket.c:2771 [inline] __se_sys_sendmmsg net/socket.c:2768 [inline]
    __x64_sys_sendmmsg+0xbc/0x120 net/socket.c:2768 x64_sys_call+0xb6e/0x3ba0
    arch/x86/include/generated/asm/syscalls_64.h:308 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f CPU: 0 UID: 0
    PID: 5460 Comm: syz.2.33 Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 (CVE-2024-50033)

  - In the Linux kernel, the following vulnerability has been resolved: thermal: intel: int340x: processor:
    Fix warning during module unload The processor_thermal driver uses pcim_device_enable() to enable a PCI
    device, which means the device will be automatically disabled on driver detach. Thus there is no need to
    call pci_disable_device() again on it. With recent PCI device resource management improvements, e.g.
    commit f748a07a0b64 (PCI: Remove legacy pcim_release()), this problem is exposed and triggers the
    warining below. [ 224.010735] proc_thermal_pci 0000:00:04.0: disabling already-disabled device [
    224.010747] WARNING: CPU: 8 PID: 4442 at drivers/pci/pci.c:2250 pci_disable_device+0xe5/0x100 ... [
    224.010844] Call Trace: [ 224.010845] <TASK> [ 224.010847] ? show_regs+0x6d/0x80 [ 224.010851] ?
    __warn+0x8c/0x140 [ 224.010854] ? pci_disable_device+0xe5/0x100 [ 224.010856] ? report_bug+0x1c9/0x1e0 [
    224.010859] ? handle_bug+0x46/0x80 [ 224.010862] ? exc_invalid_op+0x1d/0x80 [ 224.010863] ?
    asm_exc_invalid_op+0x1f/0x30 [ 224.010867] ? pci_disable_device+0xe5/0x100 [ 224.010869] ?
    pci_disable_device+0xe5/0x100 [ 224.010871] ? kfree+0x21a/0x2b0 [ 224.010873]
    pcim_disable_device+0x20/0x30 [ 224.010875] devm_action_release+0x16/0x20 [ 224.010878]
    release_nodes+0x47/0xc0 [ 224.010880] devres_release_all+0x9f/0xe0 [ 224.010883]
    device_unbind_cleanup+0x12/0x80 [ 224.010885] device_release_driver_internal+0x1ca/0x210 [ 224.010887]
    driver_detach+0x4e/0xa0 [ 224.010889] bus_remove_driver+0x6f/0xf0 [ 224.010890]
    driver_unregister+0x35/0x60 [ 224.010892] pci_unregister_driver+0x44/0x90 [ 224.010894]
    proc_thermal_pci_driver_exit+0x14/0x5f0 [processor_thermal_device_pci] ... [ 224.010921] ---[ end trace
    0000000000000000 ]--- Remove the excess pci_disable_device() calls. [ rjw: Subject and changelog edits ]
    (CVE-2024-50093)

  - In the Linux kernel, the following vulnerability has been resolved: arm64: probes: Remove broken LDR
    (literal) uprobe support The simulate_ldr_literal() and simulate_ldrsw_literal() functions are unsafe to
    use for uprobes. Both functions were originally written for use with kprobes, and access memory with plain
    C accesses. When uprobes was added, these were reused unmodified even though they cannot safely access
    user memory. There are three key problems: 1) The plain C accesses do not have corresponding extable
    entries, and thus if they encounter a fault the kernel will treat these as unintentional accesses to user
    memory, resulting in a BUG() which will kill the kernel thread, and likely lead to further issues (e.g.
    lockup or panic()). 2) The plain C accesses are subject to HW PAN and SW PAN, and so when either is in
    use, any attempt to simulate an access to user memory will fault. Thus neither simulate_ldr_literal() nor
    simulate_ldrsw_literal() can do anything useful when simulating a user instruction on any system with HW
    PAN or SW PAN. 3) The plain C accesses are privileged, as they run in kernel context, and in practice can
    access a small range of kernel virtual addresses. The instructions they simulate have a range of +/-1MiB,
    and since the simulated instructions must itself be a user instructions in the TTBR0 address range, these
    can address the final 1MiB of the TTBR1 acddress range by wrapping downwards from an address in the first
    1MiB of the TTBR0 address range. In contemporary kernels the last 8MiB of TTBR1 address range is reserved,
    and accesses to this will always fault, meaning this is no worse than (1). Historically, it was
    theoretically possible for the linear map or vmemmap to spill into the final 8MiB of the TTBR1 address
    range, but in practice this is extremely unlikely to occur as this would require either: * Having enough
    physical memory to fill the entire linear map all the way to the final 1MiB of the TTBR1 address range. *
    Getting unlucky with KASLR randomization of the linear map such that the populated region happens to
    overlap with the last 1MiB of the TTBR address range. ... and in either case if we were to spill into the
    final page there would be larger problems as the final page would alias with error pointers. Practically
    speaking, (1) and (2) are the big issues. Given there have been no reports of problems since the broken
    code was introduced, it appears that no-one is relying on probing these instructions with uprobes. Avoid
    these issues by not allowing uprobes on LDR (literal) and LDRSW (literal), limiting the use of
    simulate_ldr_literal() and simulate_ldrsw_literal() to kprobes. Attempts to place uprobes on LDR (literal)
    and LDRSW (literal) will be rejected as arm_probe_decode_insn() will return INSN_REJECTED. In future we
    can consider introducing working uprobes support for these instructions, but this will require more
    significant work. (CVE-2024-50099)

  - In the Linux kernel, the following vulnerability has been resolved: xfrm: fix one more kernel-infoleak in
    algo dumping During fuzz testing, the following issue was discovered: BUG: KMSAN: kernel-infoleak in
    _copy_to_iter+0x598/0x2a30 _copy_to_iter+0x598/0x2a30 __skb_datagram_iter+0x168/0x1060
    skb_copy_datagram_iter+0x5b/0x220 netlink_recvmsg+0x362/0x1700 sock_recvmsg+0x2dc/0x390
    __sys_recvfrom+0x381/0x6d0 __x64_sys_recvfrom+0x130/0x200 x64_sys_call+0x32c8/0x3cc0
    do_syscall_64+0xd8/0x1c0 entry_SYSCALL_64_after_hwframe+0x79/0x81 Uninit was stored to memory at:
    copy_to_user_state_extra+0xcc1/0x1e00 dump_one_state+0x28c/0x5f0 xfrm_state_walk+0x548/0x11e0
    xfrm_dump_sa+0x1e0/0x840 netlink_dump+0x943/0x1c40 __netlink_dump_start+0x746/0xdb0
    xfrm_user_rcv_msg+0x429/0xc00 netlink_rcv_skb+0x613/0x780 xfrm_netlink_rcv+0x77/0xc0
    netlink_unicast+0xe90/0x1280 netlink_sendmsg+0x126d/0x1490 __sock_sendmsg+0x332/0x3d0
    ____sys_sendmsg+0x863/0xc30 ___sys_sendmsg+0x285/0x3e0 __x64_sys_sendmsg+0x2d6/0x560
    x64_sys_call+0x1316/0x3cc0 do_syscall_64+0xd8/0x1c0 entry_SYSCALL_64_after_hwframe+0x79/0x81 Uninit was
    created at: __kmalloc+0x571/0xd30 attach_auth+0x106/0x3e0 xfrm_add_sa+0x2aa0/0x4230
    xfrm_user_rcv_msg+0x832/0xc00 netlink_rcv_skb+0x613/0x780 xfrm_netlink_rcv+0x77/0xc0
    netlink_unicast+0xe90/0x1280 netlink_sendmsg+0x126d/0x1490 __sock_sendmsg+0x332/0x3d0
    ____sys_sendmsg+0x863/0xc30 ___sys_sendmsg+0x285/0x3e0 __x64_sys_sendmsg+0x2d6/0x560
    x64_sys_call+0x1316/0x3cc0 do_syscall_64+0xd8/0x1c0 entry_SYSCALL_64_after_hwframe+0x79/0x81 Bytes 328-379
    of 732 are uninitialized Memory access of size 732 starts at ffff88800e18e000 Data copied to user address
    00007ff30f48aff0 CPU: 2 PID: 18167 Comm: syz-executor.0 Not tainted 6.8.11 #1 Hardware name: QEMU Standard
    PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 Fixes copying of xfrm algorithms where some random data
    of the structure fields can end up in userspace. Padding in structures may be filled with random (possibly
    sensitve) data and should never be given directly to user-space. A similar issue was resolved in the
    commit 8222d5910dae (xfrm: Zero padding when dumping algos and encap) Found by Linux Verification Center
    (linuxtesting.org) with Syzkaller. (CVE-2024-50110)

  - In the Linux kernel, the following vulnerability has been resolved: net: sched: fix use-after-free in
    taprio_change() In 'taprio_change()', 'admin' pointer may become dangling due to sched switch / removal
    caused by 'advance_sched()', and critical section protected by 'q->current_entry_lock' is too small to
    prevent from such a scenario (which causes use-after-free detected by KASAN). Fix this by prefer
    'rcu_replace_pointer()' over 'rcu_assign_pointer()' to update 'admin' immediately before an attempt to
    schedule freeing. (CVE-2024-50127)

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: bpf: must hold reference on
    net namespace BUG: KASAN: slab-use-after-free in __nf_unregister_net_hook+0x640/0x6b0 Read of size 8 at
    addr ffff8880106fe400 by task repro/72= bpf_nf_link_release+0xda/0x1e0 bpf_link_free+0x139/0x2d0
    bpf_link_release+0x68/0x80 __fput+0x414/0xb60 Eric says: It seems that bpf was able to defer the
    __nf_unregister_net_hook() after exit()/close() time. Perhaps a netns reference is missing, because the
    netns has been dismantled/freed already. bpf_nf_link_attach() does : link->net = net; But I do not see a
    reference being taken on net. Add such a reference and release it after hook unreg. Note that I was unable
    to get syzbot reproducer to work, so I do not know if this resolves this splat. (CVE-2024-50130)

  - In the Linux kernel, the following vulnerability has been resolved: xfrm: validate new SA's prefixlen
    using SA family when sel.family is unset This expands the validation introduced in commit 07bf7908950a
    (xfrm: Validate address prefix lengths in the xfrm selector.) syzbot created an SA with
    usersa.sel.family = AF_UNSPEC usersa.sel.prefixlen_s = 128 usersa.family = AF_INET Because of the
    AF_UNSPEC selector, verify_newsa_info doesn't put limits on prefixlen_{s,d}. But then copy_from_user_state
    sets x->sel.family to usersa.family (AF_INET). Do the same conversion in verify_newsa_info before
    validating prefixlen_{s,d}, since that's how prefixlen is going to be used later on. (CVE-2024-50142)

  - In the Linux kernel, the following vulnerability has been resolved: tcp/dccp: Don't use timer_pending() in
    reqsk_queue_unlink(). Martin KaFai Lau reported use-after-free [0] in reqsk_timer_handler().  We are
    seeing a use-after-free from a bpf prog attached to trace_tcp_retransmit_synack. The program passes the
    req->sk to the bpf_sk_storage_get_tracing kernel helper which does check for null before using it.  The
    commit 83fccfc3940c (inet: fix potential deadlock in reqsk_queue_unlink()) added timer_pending() in
    reqsk_queue_unlink() not to call del_timer_sync() from reqsk_timer_handler(), but it introduced a small
    race window. Before the timer is called, expire_timers() calls detach_timer(timer, true) to clear
    timer->entry.pprev and marks it as not pending. If reqsk_queue_unlink() checks timer_pending() just after
    expire_timers() calls detach_timer(), TCP will miss del_timer_sync(); the reqsk timer will continue
    running and send multiple SYN+ACKs until it expires. The reported UAF could happen if req->sk is close()d
    earlier than the timer expiration, which is 63s by default. The scenario would be 1.
    inet_csk_complete_hashdance() calls inet_csk_reqsk_queue_drop(), but del_timer_sync() is missed 2. reqsk
    timer is executed and scheduled again 3. req->sk is accept()ed and reqsk_put() decrements rsk_refcnt, but
    reqsk timer still has another one, and inet_csk_accept() does not clear req->sk for non-TFO sockets 4. sk
    is close()d 5. reqsk timer is executed again, and BPF touches req->sk Let's not use timer_pending() by
    passing the caller context to __inet_csk_reqsk_queue_drop(). Note that reqsk timer is pinned, so the issue
    does not happen in most use cases. [1] [0] BUG: KFENCE: use-after-free read in
    bpf_sk_storage_get_tracing+0x2e/0x1b0 Use-after-free read at 0x00000000a891fb3a (in kfence-#1):
    bpf_sk_storage_get_tracing+0x2e/0x1b0 bpf_prog_5ea3e95db6da0438_tcp_retransmit_synack+0x1d20/0x1dda
    bpf_trace_run2+0x4c/0xc0 tcp_rtx_synack+0xf9/0x100 reqsk_timer_handler+0xda/0x3d0
    run_timer_softirq+0x292/0x8a0 irq_exit_rcu+0xf5/0x320 sysvec_apic_timer_interrupt+0x6d/0x80
    asm_sysvec_apic_timer_interrupt+0x16/0x20 intel_idle_irq+0x5a/0xa0 cpuidle_enter_state+0x94/0x273
    cpu_startup_entry+0x15e/0x260 start_secondary+0x8a/0x90 secondary_startup_64_no_verify+0xfa/0xfb
    kfence-#1: 0x00000000a72cc7b6-0x00000000d97616d9, size=2376, cache=TCPv6 allocated by task 0 on cpu 9 at
    260507.901592s: sk_prot_alloc+0x35/0x140 sk_clone_lock+0x1f/0x3f0 inet_csk_clone_lock+0x15/0x160
    tcp_create_openreq_child+0x1f/0x410 tcp_v6_syn_recv_sock+0x1da/0x700 tcp_check_req+0x1fb/0x510
    tcp_v6_rcv+0x98b/0x1420 ipv6_list_rcv+0x2258/0x26e0 napi_complete_done+0x5b1/0x2990
    mlx5e_napi_poll+0x2ae/0x8d0 net_rx_action+0x13e/0x590 irq_exit_rcu+0xf5/0x320 common_interrupt+0x80/0x90
    asm_common_interrupt+0x22/0x40 cpuidle_enter_state+0xfb/0x273 cpu_startup_entry+0x15e/0x260
    start_secondary+0x8a/0x90 secondary_startup_64_no_verify+0xfa/0xfb freed by task 0 on cpu 9 at
    260507.927527s: rcu_core_si+0x4ff/0xf10 irq_exit_rcu+0xf5/0x320 sysvec_apic_timer_interrupt+0x6d/0x80
    asm_sysvec_apic_timer_interrupt+0x16/0x20 cpuidle_enter_state+0xfb/0x273 cpu_startup_entry+0x15e/0x260
    start_secondary+0x8a/0x90 secondary_startup_64_no_verify+0xfa/0xfb (CVE-2024-50154)

  - In the Linux kernel, the following vulnerability has been resolved: net: explicitly clear the sk pointer,
    when pf->create fails We have recently noticed the exact same KASAN splat as in commit 6cd4a78d962b (net:
    do not leave a dangling sk pointer, when socket creation fails). The problem is that commit did not fully
    address the problem, as some pf->create implementations do not use sk_common_release in their error paths.
    For example, we can use the same reproducer as in the above commit, but changing ping to arping. arping
    uses AF_PACKET socket and if packet_create fails, it will just sk_free the allocated sk object. While we
    could chase all the pf->create implementations and make sure they NULL the freed sk object on error from
    the socket, we can't guarantee future protocols will not make the same mistake. So it is easier to just
    explicitly NULL the sk pointer upon return from pf->create in __sock_create. We do know that pf->create
    always releases the allocated sk object on error, so if the pointer is not NULL, it is definitely
    dangling. (CVE-2024-50186)

  - In the Linux kernel, the following vulnerability has been resolved: ext4: don't set SB_RDONLY after
    filesystem errors When the filesystem is mounted with errors=remount-ro, we were setting SB_RDONLY flag to
    stop all filesystem modifications. We knew this misses proper locking (sb->s_umount) and does not go
    through proper filesystem remount procedure but it has been the way this worked since early ext2 days and
    it was good enough for catastrophic situation damage mitigation. Recently, syzbot has found a way (see
    link) to trigger warnings in filesystem freezing because the code got confused by SB_RDONLY changing under
    its hands. Since these days we set EXT4_FLAGS_SHUTDOWN on the superblock which is enough to stop all
    filesystem modifications, modifying SB_RDONLY shouldn't be needed. So stop doing that. (CVE-2024-50191)

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix out-of-bounds write in
    trie_get_next_key() trie_get_next_key() allocates a node stack with size trie->max_prefixlen, while it
    writes (trie->max_prefixlen + 1) nodes to the stack when it has full paths from the root to leaves. For
    example, consider a trie with max_prefixlen is 8, and the nodes with key 0x00/0, 0x00/1, 0x00/2, ...
    0x00/8 inserted. Subsequent calls to trie_get_next_key with _key with .prefixlen = 8 make 9 nodes be
    written on the node stack with size 8. (CVE-2024-50262)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=72037");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream bpftool package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-uki-virt-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-uki-virt-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libperf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'bpftool-7.5.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.5.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.5.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-5.14.0-533.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-533.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-uki-virt-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-uki-virt-addons-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-5.14.0-533.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-ipaclones-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-matched-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-partner-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-matched-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-matched-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-core-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-core-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-partner-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-partner-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uki-virt-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uki-virt-addons-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-matched-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-core-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-internal-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-partner-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-533.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-533.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-533.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-64k / kernel-64k-core / kernel-64k-debug / etc');
}
