#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200960);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_cve_id(
    "CVE-2021-47037",
    "CVE-2021-47070",
    "CVE-2021-47076",
    "CVE-2021-47094",
    "CVE-2021-47101",
    "CVE-2021-47105",
    "CVE-2021-47182",
    "CVE-2021-47212",
    "CVE-2023-52467",
    "CVE-2023-52476",
    "CVE-2023-52478",
    "CVE-2023-52484",
    "CVE-2023-52486",
    "CVE-2023-52492",
    "CVE-2023-52498",
    "CVE-2023-52515",
    "CVE-2023-52522",
    "CVE-2023-52527",
    "CVE-2023-52572",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52616",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2024-23307",
    "CVE-2024-23851",
    "CVE-2024-24855",
    "CVE-2024-24860",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26614",
    "CVE-2024-26627",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26645",
    "CVE-2024-26654",
    "CVE-2024-26656",
    "CVE-2024-26659",
    "CVE-2024-26661",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26680",
    "CVE-2024-26686",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26698",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26733",
    "CVE-2024-26734",
    "CVE-2024-26735",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26752",
    "CVE-2024-26759",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26769",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26787",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26808",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26840",
    "CVE-2024-26851",
    "CVE-2024-26855",
    "CVE-2024-26859",
    "CVE-2024-26862",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26875",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26889",
    "CVE-2024-26894",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26920",
    "CVE-2024-27437"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2024-1837)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking
    Releasing the `priv-lock` while iterating the `priv-multicast_list` in `ipoib_mcast_join_task()`
    opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the
    mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard
    lockup.(CVE-2023-52587)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Move scsi_host_busy() out
    of host lock for waking up EH handler Inside scsi_eh_wakeup(), scsi_host_busy() is called  checked with
    host lock every time for deciding if error handler kthread needs to be waken up. This can be too heavy in
    case of recovery, such as: - N hardware queues - queue depth is M for each hardware queue - each
    scsi_host_busy() iterates over (N * M) tag/requests If recovery is triggered in case that all requests are
    in-flight, each scsi_eh_wakeup() is strictly serialized, when scsi_eh_wakeup() is called for the last in-
    flight request, scsi_host_busy() has been run for (N * M - 1) times, and request has been iterated for
    (N*M - 1) * (N * M) times. If both N and M are big enough, hard lockup can be triggered on acquiring host
    lock, and it is observed on mpi3mr(128 hw queues, queue depth 8169). Fix the issue by calling
    scsi_host_busy() outside the host lock. We don't need the host lock for getting busy count because host
    the lock never covers that. [mkp: Drop unnecessary 'busy' variables pointed out by Bart](CVE-2024-26627)

    copy_params in drivers/md/dm-ioctl.c in the Linux kernel through 6.7.1 can attempt to allocate more than
    INT_MAX bytes, and crash, because of a missing param_kernel-data_size check. This is related to
    ctl_ioctl.(CVE-2024-23851)

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

    In the Linux kernel, the following vulnerability has been resolved: perf/x86/lbr: Filter vsyscall
    addresses We found that a panic can occur when a vsyscall is made while LBR sampling is active. If the
    vsyscall is interrupted (NMI) for perf sampling, this call sequence can occur (most recent at top):
    __insn_get_emulate_prefix() insn_get_emulate_prefix() insn_get_prefixes() insn_get_opcode()
    decode_branch_type() get_branch_type() intel_pmu_lbr_filter() intel_pmu_handle_irq()
    perf_event_nmi_handler() Within __insn_get_emulate_prefix() at frame 0, a macro is called:
    peek_nbyte_next(insn_byte_t, insn, i) Within this macro, this dereference occurs: (insn)-next_byte
    Inspecting registers at this point, the value of the next_byte field is the address of the vsyscall made,
    for example the location of the vsyscall version of gettimeofday() at 0xffffffffff600000. The access to an
    address in the vsyscall region will trigger an oops due to an unhandled page fault. To fix the bug,
    filtering for vsyscalls can be done when determining the branch type. This patch will return a 'none'
    branch if a kernel address if found to lie in the vsyscall region.(CVE-2023-52476)

    In the Linux kernel, the following vulnerability has been resolved: s390/ptrace: handle setting of fpc
    register correctly If the content of the floating point control (fpc) register of a traced process is
    modified with the ptrace interface the new value is tested for validity by temporarily loading it into the
    fpc register. This may lead to corruption of the fpc register of the tracing process: if an interrupt
    happens while the value is temporarily loaded into the fpc register, and within interrupt context floating
    point or vector registers are used, the current fp/vx registers are saved with save_fpu_regs() assuming
    they belong to user space and will be loaded into fp/vx registers when returning to user space.
    test_fp_ctl() restores the original user space fpc register value, however it will be discarded, when
    returning to user space. In result the tracer will incorrectly continue to run with the value that was
    supposed to be used for the traced process. Fix this by saving fpu register contents with save_fpu_regs()
    before using test_fp_ctl().(CVE-2023-52598)

    In the Linux kernel, the following vulnerability has been resolved: tcp: make sure init the accept_queue's
    spinlocks once When I run syz's reproduction C program locally, it causes the following issue:
    pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0!(CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved: PM: sleep: Fix possible deadlocks in
    core system-wide PM code It is reported that in low-memory situations the system-wide resume core code
    deadlocks, because async_schedule_dev() executes its argument function synchronously if it cannot allocate
    memory (and not only in that case) and that function attempts to acquire a mutex that is already held.
    Executing the argument function synchronously from within dpm_async_fn() may also be problematic for
    ordering reasons (it may cause a consumer device's resume callback to be invoked before a requisite
    supplier device's one, for example). Address this by changing the code in question to use
    async_schedule_dev_nocall() for scheduling the asynchronous execution of device suspend and resume
    functions and to directly run them synchronously if async_schedule_dev_nocall() returns
    false.(CVE-2023-52498)

    In the Linux kernel, the following vulnerability has been resolved: ceph: fix deadlock or deadcode of
    misusing dget() The lock order is incorrect between denty and its parent, we should always make sure that
    the parent get the lock first. But since this deadcode is never used and the parent dir will always be set
    from the callers, let's just remove it.(CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved: hwrng: core - Fix page fault dead lock
    on mmap-ed hwrng There is a dead-lock in the hwrng device read path. This triggers when the user reads
    from /dev/hwrng into memory also mmap-ed from /dev/hwrng. The resulting page fault triggers a recursive
    read which then dead-locks. Fix this by using a stack buffer when calling copy_to_user.(CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved: cifs: Fix UAF in
    cifs_demultiplex_thread() There is a UAF when xfstests on cifs: BUG: KASAN: use-after-free in
    smb2_is_network_name_deleted+0x27/0x160 Read of size 4 at addr ffff88810103fc08 by task cifsd/923 CPU: 1
    PID: 923 Comm: cifsd Not tainted 6.1.0-rc4+ #45 ... Call Trace: TASK dump_stack_lvl+0x34/0x44
    print_report+0x171/0x472 kasan_report+0xad/0x130 kasan_check_range+0x145/0x1a0
    smb2_is_network_name_deleted+0x27/0x160 cifs_demultiplex_thread.cold+0x172/0x5a4 kthread+0x165/0x1a0
    ret_from_fork+0x1f/0x30 /TASK Allocated by task 923: kasan_save_stack+0x1e/0x40
    kasan_set_track+0x21/0x30 __kasan_slab_alloc+0x54/0x60 kmem_cache_alloc+0x147/0x320
    mempool_alloc+0xe1/0x260 cifs_small_buf_get+0x24/0x60 allocate_buffers+0xa1/0x1c0
    cifs_demultiplex_thread+0x199/0x10d0 kthread+0x165/0x1a0 ret_from_fork+0x1f/0x30 Freed by task 921:
    kasan_save_stack+0x1e/0x40 kasan_set_track+0x21/0x30 kasan_save_free_info+0x2a/0x40
    ____kasan_slab_free+0x143/0x1b0 kmem_cache_free+0xe3/0x4d0 cifs_small_buf_release+0x29/0x90
    SMB2_negotiate+0x8b7/0x1c60 smb2_negotiate+0x51/0x70 cifs_negotiate_protocol+0xf0/0x160
    cifs_get_smb_ses+0x5fa/0x13c0 mount_get_conns+0x7a/0x750 cifs_mount+0x103/0xd00
    cifs_smb3_do_mount+0x1dd/0xcb0 smb3_get_tree+0x1d5/0x300 vfs_get_tree+0x41/0xf0 path_mount+0x9b3/0xdd0
    __x64_sys_mount+0x190/0x1d0 do_syscall_64+0x35/0x80 entry_SYSCALL_64_after_hwframe+0x46/0xb0 The UAF is
    because: mount(pid: 921) | cifsd(pid: 923) -------------------------------|-------------------------------
    | cifs_demultiplex_thread SMB2_negotiate | cifs_send_recv | compound_send_recv | smb_send_rqst |
    wait_for_response | wait_event_state [1] | | standard_receive3 | cifs_handle_standard | handle_mid | mid-
    resp_buf = buf; [2] | dequeue_mid [3] KILL the process [4] | resp_iov[i].iov_base = buf | free_rsp_buf
    [5] | | is_network_name_deleted [6] | callback 1. After send request to server, wait the response until
    mid-mid_state != SUBMITTED; 2. Receive response from server, and set it to mid; 3. Set the mid state to
    RECEIVED; 4. Kill the process, the mid state already RECEIVED, get 0; 5. Handle and release the negotiate
    response; 6. UAF. It can be easily reproduce with add some delay in [3] - [6]. Only sync call has the
    problem since async call's callback is executed in cifsd process. Add an extra state to mark the mid state
    to READY before wakeup the waitter, then it can get the resp safely.(CVE-2023-52572)

    In the Linux kernel, the following vulnerability has been resolved: iommu/arm-smmu-v3: Fix soft lockup
    triggered by arm_smmu_mm_invalidate_range When running an SVA case, the following soft lockup is
    triggered: -------------------------------------------------------------------- watchdog: BUG: soft lockup
    - CPU#244 stuck for 26s! pstate: 83400009 (Nzcv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--) pc :
    arm_smmu_cmdq_issue_cmdlist+0x178/0xa50 lr : arm_smmu_cmdq_issue_cmdlist+0x150/0xa50 sp : ffff8000d83ef290
    x29: ffff8000d83ef290 x28: 000000003b9aca00 x27: 0000000000000000 x26: ffff8000d83ef3c0 x25:
    da86c0812194a0e8 x24: 0000000000000000 x23: 0000000000000040 x22: ffff8000d83ef340 x21: ffff0000c63980c0
    x20: 0000000000000001 x19: ffff0000c6398080 x18: 0000000000000000 x17: 0000000000000000 x16:
    0000000000000000 x15: ffff3000b4a3bbb0 x14: ffff3000b4a30888 x13: ffff3000b4a3cf60 x12: 0000000000000000
    x11: 0000000000000000 x10: 0000000000000000 x9 : ffffc08120e4d6bc x8 : 0000000000000000 x7 :
    0000000000000000 x6 : 0000000000048cfa x5 : 0000000000000000 x4 : 0000000000000001 x3 : 000000000000000a
    x2 : 0000000080000000 x1 : 0000000000000000 x0 : 0000000000000001 Call trace:
    arm_smmu_cmdq_issue_cmdlist+0x178/0xa50 __arm_smmu_tlb_inv_range+0x118/0x254
    arm_smmu_tlb_inv_range_asid+0x6c/0x130 arm_smmu_mm_invalidate_range+0xa0/0xa4
    __mmu_notifier_invalidate_range_end+0x88/0x120 unmap_vmas+0x194/0x1e0 unmap_region+0xb4/0x144
    do_mas_align_munmap+0x290/0x490 do_mas_munmap+0xbc/0x124 __vm_munmap+0xa8/0x19c
    __arm64_sys_munmap+0x28/0x50 invoke_syscall+0x78/0x11c el0_svc_common.constprop.0+0x58/0x1c0
    do_el0_svc+0x34/0x60 el0_svc+0x2c/0xd4 el0t_64_sync_handler+0x114/0x140 el0t_64_sync+0x1a4/0x1a8
    -------------------------------------------------------------------- Note that since 6.6-rc1 the
    arm_smmu_mm_invalidate_range above is renamed to 'arm_smmu_mm_arch_invalidate_secondary_tlbs', yet the
    problem remains. The commit 06ff87bae8d3 ('arm64: mm: remove unused functions and variable protoypes')
    fixed a similar lockup on the CPU MMU side. Yet, it can occur to SMMU too, since
    arm_smmu_mm_arch_invalidate_secondary_tlbs() is called typically next to MMU tlb flush function, e.g.
    tlb_flush_mmu_tlbonly { tlb_flush { __flush_tlb_range { // check MAX_TLBI_OPS } }
    mmu_notifier_arch_invalidate_secondary_tlbs { arm_smmu_mm_arch_invalidate_secondary_tlbs { // does not
    check MAX_TLBI_OPS } } } Clone a CMDQ_MAX_TLBI_OPS from the MAX_TLBI_OPS in tlbflush.h, since in an SVA
    case SMMU uses the CPU page table, so it makes sense to align with the tlbflush code. Then, replace per-
    page TLBI commands with a single per-asid TLBI command, if the request size hits this
    threshold.(CVE-2023-52484)

    In the Linux kernel, the following vulnerability has been resolved: crypto: lib/mpi - Fix unexpected
    pointer access in mpi_ec_init When the mpi_ec_ctx structure is initialized, some fields are not cleared,
    causing a crash when referencing the field when the structure was released. Initially, this issue was
    ignored because memory for mpi_ec_ctx is allocated with the __GFP_ZERO flag. For example, this error will
    be triggered when calculating the Za value for SM2 separately.(CVE-2023-52616)

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

    In the Linux kernel, the following vulnerability has been resolved: pstore/ram: Fix crash when setting
    number of cpus to an odd number When the number of cpu cores is adjusted to 7 or other odd numbers, the
    zone size will become an odd number. The address of the zone will become: addr of zone0 = BASE addr of
    zone1 = BASE + zone_size addr of zone2 = BASE + zone_size*2 ... The address of zone1/3/5/7 will be mapped
    to non-alignment va. Eventually crashes will occur when accessing these va. So, use ALIGN_DOWN() to make
    sure the zone size is even to avoid this bug.(CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Ensure visibility when
    inserting an element into tracing_map Running the following two commands in parallel on a multi-processor
    AArch64 machine can sporadically produce an unexpected warning about duplicate histogram entries: $ while
    true; do echo hist:key=id.syscall:val=hitcount  \
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/trigger cat
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/hist sleep 0.001 done $ stress-ng --sysbadaddr
    $(nproc) The warning looks as follows: [ 2911.172474] ------------[ cut here ]------------ [ 2911.173111]
    Duplicates detected: 1 [ 2911.173574] WARNING: CPU: 2 PID: 12247 at kernel/trace/tracing_map.c:983
    tracing_map_sort_entries+0x3e0/0x408 [ 2911.174702] Modules linked in: iscsi_ibft(E) iscsi_boot_sysfs(E)
    rfkill(E) af_packet(E) nls_iso8859_1(E) nls_cp437(E) vfat(E) fat(E) ena(E) tiny_power_button(E)
    qemu_fw_cfg(E) button(E) fuse(E) efi_pstore(E) ip_tables(E) x_tables(E) xfs(E) libcrc32c(E) aes_ce_blk(E)
    aes_ce_cipher(E) crct10dif_ce(E) polyval_ce(E) polyval_generic(E) ghash_ce(E) gf128mul(E) sm4_ce_gcm(E)
    sm4_ce_ccm(E) sm4_ce(E) sm4_ce_cipher(E) sm4(E) sm3_ce(E) sm3(E) sha3_ce(E) sha512_ce(E) sha512_arm64(E)
    sha2_ce(E) sha256_arm64(E) nvme(E) sha1_ce(E) nvme_core(E) nvme_auth(E) t10_pi(E) sg(E) scsi_mod(E)
    scsi_common(E) efivarfs(E) [ 2911.174738] Unloaded tainted modules: cppc_cpufreq(E):1 [ 2911.180985] CPU:
    2 PID: 12247 Comm: cat Kdump: loaded Tainted: G E 6.7.0-default #2
    1b58bbb22c97e4399dc09f92d309344f69c44a01 [ 2911.182398] Hardware name: Amazon EC2 c7g.8xlarge/, BIOS 1.0
    11/1/2018 [ 2911.183208] pstate: 61400005 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--) [ 2911.184038] pc
    : tracing_map_sort_entries+0x3e0/0x408 [ 2911.184667] lr : tracing_map_sort_entries+0x3e0/0x408 [
    2911.185310] sp : ffff8000a1513900 [ 2911.185750] x29: ffff8000a1513900 x28: ffff0003f272fe80 x27:
    0000000000000001 [ 2911.186600] x26: ffff0003f272fe80 x25: 0000000000000030 x24: 0000000000000008 [
    2911.187458] x23: ffff0003c5788000 x22: ffff0003c16710c8 x21: ffff80008017f180 [ 2911.188310] x20:
    ffff80008017f000 x19: ffff80008017f180 x18: ffffffffffffffff [ 2911.189160] x17: 0000000000000000 x16:
    0000000000000000 x15: ffff8000a15134b8 [ 2911.190015] x14: 0000000000000000 x13: 205d373432323154 x12:
    5b5d313131333731 [ 2911.190844] x11: 00000000fffeffff x10: 00000000fffeffff x9 : ffffd1b78274a13c [
    2911.191716] x8 : 000000000017ffe8 x7 : c0000000fffeffff x6 : 000000000057ffa8 [ 2911.192554] x5 :
    ffff0012f6c24ec0 x4 : 0000000000000000 x3 : ffff2e5b72b5d000 [ 2911.193404] x2 : 0000000000000000 x1 :
    0000000000000000 x0 : ffff0003ff254480 [ 2911.194259] Call trace: [ 2911.194626]
    tracing_map_sort_entries+0x3e0/0x408 [ 2911.195220] hist_show+0x124/0x800 [ 2911.195692]
    seq_read_iter+0x1d4/0x4e8 [ 2911.196193] seq_read+0xe8/0x138 [ 2911.196638] vfs_read+0xc8/0x300 [
    2911.197078] ksys_read+0x70/0x108 [ 2911.197534] __arm64_sys_read+0x24/0x38 [ 2911.198046]
    invoke_syscall+0x78/0x108 [ 2911.198553] el0_svc_common.constprop.0+0xd0/0xf8 [ 2911.199157]
    do_el0_svc+0x28/0x40 [ 2911.199613] el0_svc+0x40/0x178 [ 2911.200048] el0t_64_sync_handler+0x13c/0x158 [
    2911.200621] el0t_64_sync+0x1a8/0x1b0 [ 2911.201115] ---[ end trace 0000000000000000 ]--- The problem
    appears to be caused by CPU reordering of writes issued from __tracing_map_insert(). The check for the
    presence of an element with a given key in this function is: val = READ_ONCE(entry-val); if (val 
    keys_match(key, val-key, map-key_size)) ... The write of a new entry is: elt = get_free_elt(map);
    memcpy(elt-key, key, map-key_size); entry-val = elt; The 'memcpy(elt-key, key, map-
    key_size);' and 'entry-val = elt;' stores may become visible in the reversed order on another CPU.
    This second CPU might then incorrectly determine that a new key doesn't match an already present val-
    key and subse ---truncated---(CVE-2024-26645)

    Integer Overflow or Wraparound vulnerability in Linux Linux kernel kernel on Linux, x86, ARM (md, raid,
    raid5 modules) allows Forced Integer Overflow.(CVE-2024-23307)

    In the Linux kernel, the following vulnerability has been resolved: llc: Drop support for ETH_P_TR_802_2.
    syzbot reported an uninit-value bug below. [0] llc supports ETH_P_802_2 (0x0004) and used to support
    ETH_P_TR_802_2 (0x0011), and syzbot abused the latter to trigger the bug.(CVE-2024-26635)

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

    In the Linux kernel, the following vulnerability has been resolved:ASoC: q6afe-clocks: fix reprobing of
    the driver,Q6afe-clocks driver can get reprobed. For example if the APR services are restarted after the
    firmware crash. However currently Q6afe-clocks driver will oops because hw.init will get cleared during
    first _probe call. Rewrite the driver to fill the clock data at runtime rather than using big static array
    of clocks.(CVE-2021-47037)

    In the Linux kernel, the following vulnerability has been resolved:uio_hv_generic: Fix another memory leak
    in error handling paths,Memory allocated by 'vmbus_alloc_ring()' at the beginning of the probe function is
    never freed in the error handling path.Add the missing 'vmbus_free_ring()' call.Note that it is already
    freed in the .remove function.(CVE-2021-47070)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid online resizing failures
    due to oversized flex bg When we online resize an ext4 filesystem with a oversized flexbg_size, mkfs.ext4
    -F -G 67108864 $dev -b 4096 100M mount $dev $dir resize2fs $dev 16G the following WARN_ON is triggered:
    ================================================================== WARNING: CPU: 0 PID: 427 at
    mm/page_alloc.c:4402 __alloc_pages+0x411/0x550 Modules linked in: sg(E) CPU: 0 PID: 427 Comm: resize2fs
    Tainted: G E 6.6.0-rc5+ #314 RIP: 0010:__alloc_pages+0x411/0x550 Call Trace: TASK
    __kmalloc_large_node+0xa2/0x200 __kmalloc+0x16e/0x290 ext4_resize_fs+0x481/0xd80
    __ext4_ioctl+0x1616/0x1d90 ext4_ioctl+0x12/0x20 __x64_sys_ioctl+0xf0/0x150 do_syscall_64+0x3b/0x90
    ================================================================== This is because flexbg_size is too
    large and the size of the new_group_data array to be allocated exceeds MAX_ORDER. Currently, the minimum
    value of MAX_ORDER is 8, the minimum value of PAGE_SIZE is 4096, the corresponding maximum number of
    groups that can be allocated is: (PAGE_SIZE  MAX_ORDER) / sizeof(struct ext4_new_group_data) 
    21845 And the value that is down-aligned to the power of 2 is 16384. Therefore, this value is defined as
    MAX_RESIZE_BG, and the number of groups added each time does not exceed this value during resizing, and is
    added multiple times to complete the online resizing. The difference is that the metadata in a flex_bg may
    be more dispersed.(CVE-2023-52622)

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

    A race condition was found in the Linux kernel's scsi device driver in lpfc_unregister_fcf_rescan()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24855)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: mark set as dead
    when unbinding anonymous set with timeout While the rhashtable set gc runs asynchronously, a race allows
    it to collect elements from anonymous sets with timeouts while it is being released from the commit path.
    Mingi Cho originally reported this issue in a different path in 6.1.x with a pipapo set with low timeouts
    which is not possible upstream since 7395dfacfff6 ('netfilter: nf_tables: use timestamp to check for set
    element timeout'). Fix this by setting on the dead flag for anonymous sets to skip async gc in this case.
    According to 08e4c8c5919f ('netfilter: nf_tables: mark newset as dead on transaction abort'), Florian
    plans to accelerate abort path by releasing objects via workqueue, therefore, this sets on the dead flag
    for abort path too.(CVE-2024-26643)

    In the Linux kernel, the following vulnerability has been resolved:netfilter: nf_tables: disallow
    anonymous set with timeout flag.Anonymous sets are never used with timeout from userspace, reject
    this.Exception to this rule is NFT_SET_EVAL to ensure legacy meters still work.(CVE-2024-26642)

    In the Linux kernel, the following vulnerability has been resolved:netfilter: nf_tables: disallow timeout
    for anonymous sets.Never used from userspace, disallow these parameters.(CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved:net: fix possible store tearing in
    neigh_periodic_work().While looking at a related syzbot report involving neigh_periodic_work(),I found
    that I forgot to add an annotation when deleting an RCU protected item from a list.Readers use
    rcu_deference(*np), we need to use either rcu_assign_pointer() or WRITE_ONCE() on writer side to prevent
    store tearing.I use rcu_assign_pointer() to have lockdep support,this was the choice made in
    neigh_flush_dev().(CVE-2023-52522)

    In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev-stats fields. Handles updates to
    dev-stats.tx_dropped while we are at it.(CVE-2023-52578)

    In the Linux kernel, the following vulnerability has been resolved:vfio/platform: Create persistent IRQ
    handlers.The vfio-platform SET_IRQS ioctl currently allows loopback triggering of.an interrupt before a
    signaling eventfd has been configured by the user,which thereby allows a NULL pointer dereference.Rather
    than register the IRQ relative to a valid trigger, register all IRQs in a disabled state in the device
    open path.  This allows mask operations on the IRQ to nest within the overall enable state governed by a
    valid eventfd signal.  This decouples @masked, protected by the @locked spinlock from @trigger, protected
    via the @igate mutex.In doing so, it_x27;s guaranteed that changes to @trigger cannot race the IRQ
    handlers because the IRQ handler is synchronously disabled before modifying the trigger, and loopback
    triggering of the IRQ via ioctl is safe due to serialization with trigger changes via igate.For
    compatibility, request_irq() failures are maintained to be local to the SET_IRQS ioctl rather than a fatal
    error in the open device path.This allows, for example, a userspace driver with polling mode support to
    continue to work regardless of moving the request_irq() call site.This necessarily blocks all SET_IRQS
    access to the failed index.(CVE-2024-26813)

    A race condition was found in the Linux kernel's media/xc4000 device driver in xc4000
    xc4000_get_frequency() function. This can result in return value overflow issue, possibly leading to
    malfunction or denial of service issue.(CVE-2024-24861)

    create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero
    bytes, and crash, because of a missing check for ubi-leb_size.(CVE-2024-25739)

    In the Linux kernel, the following vulnerability has been resolved:crypto: scomp - fix req-dst buffer
    overflow.The req-dst buffer size should be checked before copying from the scomp_scratch-dst to
    avoid req-dst buffer overflow problem.(CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved: KVM: x86/mmu: Don't advance iterator
    after restart due to yielding After dropping mmu_lock in the TDP MMU, restart the iterator during
    tdp_iter_next() and do not advance the iterator. Advancing the iterator results in skipping the top-level
    SPTE and all its children, which is fatal if any of the skipped SPTEs were not visited before yielding.
    When zapping all SPTEs, i.e. when min_level == root_level, restarting the iter and then invoking
    tdp_iter_next() is always fatal if the current gfn has as a valid SPTE, as advancing the iterator results
    in try_step_side() skipping the current gfn, which wasn't visited before yielding. Sprinkle WARNs on iter-
    yielded being true in various helpers that are often used in conjunction with yielding, and tag the
    helper with __must_check to reduce the probabily of improper usage. Failing to zap a top-level SPTE
    manifests in one of two ways. If a valid SPTE is skipped by both kvm_tdp_mmu_zap_all() and
    kvm_tdp_mmu_put_root(), the shadow page will be leaked and KVM will WARN accordingly. WARNING: CPU: 1 PID:
    3509 at arch/x86/kvm/mmu/tdp_mmu.c:46 [kvm] RIP: 0010:kvm_mmu_uninit_tdp_mmu+0x3e/0x50 [kvm] Call Trace:
    TASK kvm_arch_destroy_vm+0x130/0x1b0 [kvm] kvm_destroy_vm+0x162/0x2a0 [kvm]
    kvm_vcpu_release+0x34/0x60 [kvm] __fput+0x82/0x240 task_work_run+0x5c/0x90 do_exit+0x364/0xa10 ?
    futex_unqueue+0x38/0x60 do_group_exit+0x33/0xa0 get_signal+0x155/0x850
    arch_do_signal_or_restart+0xed/0x750 exit_to_user_mode_prepare+0xc5/0x120
    syscall_exit_to_user_mode+0x1d/0x40 do_syscall_64+0x48/0xc0 entry_SYSCALL_64_after_hwframe+0x44/0xae If
    kvm_tdp_mmu_zap_all() skips a gfn/SPTE but that SPTE is then zapped by kvm_tdp_mmu_put_root(), KVM
    triggers a use-after-free in the form of marking a struct page as dirty/accessed after it has been put
    back on the free list. This directly triggers a WARN due to encountering a page with page_count() == 0,
    but it can also lead to data corruption and additional errors in the kernel. WARNING: CPU: 7 PID: 1995658
    at arch/x86/kvm/../../../virt/kvm/kvm_main.c:171 RIP: 0010:kvm_is_zone_device_pfn.part.0+0x9e/0xd0 [kvm]
    Call Trace: TASK kvm_set_pfn_dirty+0x120/0x1d0 [kvm] __handle_changed_spte+0x92e/0xca0 [kvm]
    __handle_changed_spte+0x63c/0xca0 [kvm] __handle_changed_spte+0x63c/0xca0 [kvm]
    __handle_changed_spte+0x63c/0xca0 [kvm] zap_gfn_range+0x549/0x620 [kvm] kvm_tdp_mmu_put_root+0x1b6/0x270
    [kvm] mmu_free_root_page+0x219/0x2c0 [kvm] kvm_mmu_free_roots+0x1b4/0x4e0 [kvm] kvm_mmu_unload+0x1c/0xa0
    [kvm] kvm_arch_destroy_vm+0x1f2/0x5c0 [kvm] kvm_put_kvm+0x3b1/0x8b0 [kvm] kvm_vcpu_release+0x4e/0x70 [kvm]
    __fput+0x1f7/0x8c0 task_work_run+0xf8/0x1a0 do_exit+0x97b/0x2230 do_group_exit+0xda/0x2a0
    get_signal+0x3be/0x1e50 arch_do_signal_or_restart+0x244/0x17f0 exit_to_user_mode_prepare+0xcb/0x120
    syscall_exit_to_user_mode+0x1d/0x40 do_syscall_64+0x4d/0x90 entry_SYSCALL_64_after_hwframe+0x44/0xae Note,
    the underlying bug existed even before commit 1af4a96025b3 ('KVM: x86/mmu: Yield in TDU MMU iter even if
    no SPTES changed') moved calls to tdp_mmu_iter_cond_resched() to the beginning of loops, as KVM could
    still incorrectly advance past a top-level entry when yielding on a lower-level entry. But with respect to
    leaking shadow pages, the bug was introduced by yielding before processing the current gfn. Alternatively,
    tdp_mmu_iter_cond_resched() could simply fall through, or callers could jump to their 'retry' label. The
    downside of that approach is that tdp_mmu_iter_cond_resched() _must_ be called before anything else in the
    loop, and there's no easy way to enfornce that requirement. Ideally, KVM would handling the cond_resched()
    fully within the iterator macro (the code is actually quite clean) and avoid this entire class of bugs,
    but that is extremely difficult do wh ---truncated---(CVE-2021-47094)

    In the Linux kernel, the following vulnerability has been resolved: fs,hugetlb: fix NULL pointer
    dereference in hugetlbs_fill_super When configuring a hugetlb filesystem via the fsconfig() syscall, there
    is a possible NULL dereference in hugetlbfs_fill_super() caused by assigning NULL to ctx-hstate in
    hugetlbfs_parse_param() when the requested pagesize is non valid. E.g: Taking the following steps: fd =
    fsopen('hugetlbfs', FSOPEN_CLOEXEC); fsconfig(fd, FSCONFIG_SET_STRING, 'pagesize', '1024', 0);
    fsconfig(fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0); Given that the requested 'pagesize' is invalid, ctxt-
    hstate will be replaced with NULL, losing its previous value, and we will print an error: ... ... case
    Opt_pagesize: ps = memparse(param-string, rest); ctx-hstate = h; if (!ctx-hstate) {
    pr_err('Unsupported page size %lu MB\n', ps / SZ_1M); return -EINVAL; } return 0; ... ... This is a
    problem because later on, we will dereference ctxt-hstate in hugetlbfs_fill_super() ... ... sb-
    s_blocksize = huge_page_size(ctx-hstate); ... ... Causing below Oops. Fix this by replacing cxt-
    hstate value only when then pagesize is known to be valid. kernel: hugetlbfs: Unsupported page size 0
    MB kernel: BUG: kernel NULL pointer dereference, address: 0000000000000028 kernel: #PF: supervisor read
    access in kernel mode kernel: #PF: error_code(0x0000) - not-present page kernel: PGD 800000010f66c067 P4D
    800000010f66c067 PUD 1b22f8067 PMD 0 kernel: Oops: 0000 [#1] PREEMPT SMP PTI kernel: CPU: 4 PID: 5659
    Comm: syscall Tainted: G E 6.8.0-rc2-default+ #22 5a47c3fef76212addcc6eb71344aabc35190ae8f kernel:
    Hardware name: Intel Corp. GROVEPORT/GROVEPORT, BIOS GVPRCRB1.86B.0016.D04.1705030402 05/03/2017 kernel:
    RIP: 0010:hugetlbfs_fill_super+0xb4/0x1a0 kernel: Code: 48 8b 3b e8 3e c6 ed ff 48 85 c0 48 89 45 20 0f 84
    d6 00 00 00 48 b8 ff ff ff ff ff ff ff 7f 4c 89 e7 49 89 44 24 20 48 8b 03 8b 48 28 b8 00 10 00 00
    48 d3 e0 49 89 44 24 18 48 8b 03 8b 40 28 kernel: RSP: 0018:ffffbe9960fcbd48 EFLAGS: 00010246 kernel: RAX:
    0000000000000000 RBX: ffff9af5272ae780 RCX: 0000000000372004 kernel: RDX: ffffffffffffffff RSI:
    ffffffffffffffff RDI: ffff9af555e9b000 kernel: RBP: ffff9af52ee66b00 R08: 0000000000000040 R09:
    0000000000370004 kernel: R10: ffffbe9960fcbd48 R11: 0000000000000040 R12: ffff9af555e9b000 kernel: R13:
    ffffffffa66b86c0 R14: ffff9af507d2f400 R15: ffff9af507d2f400 kernel: FS: 00007ffbc0ba4740(0000)
    GS:ffff9b0bd7000000(0000) knlGS:0000000000000000 kernel: CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
    kernel: CR2: 0000000000000028 CR3: 00000001b1ee0000 CR4: 00000000001506f0 kernel: Call Trace: kernel:
    TASK kernel: ? __die_body+0x1a/0x60 kernel: ? page_fault_oops+0x16f/0x4a0 kernel: ?
    search_bpf_extables+0x65/0x70 kernel: ? fixup_exception+0x22/0x310 kernel: ? exc_page_fault+0x69/0x150
    kernel: ? asm_exc_page_fault+0x22/0x30 kernel: ? __pfx_hugetlbfs_fill_super+0x10/0x10 kernel: ?
    hugetlbfs_fill_super+0xb4/0x1a0 kernel: ? hugetlbfs_fill_super+0x28/0x1a0 kernel: ?
    __pfx_hugetlbfs_fill_super+0x10/0x10 kernel: vfs_get_super+0x40/0xa0 kernel: ?
    __pfx_bpf_lsm_capable+0x10/0x10 kernel: vfs_get_tree+0x25/0xd0 kernel: vfs_cmd_create+0x64/0xe0 kernel:
    __x64_sys_fsconfig+0x395/0x410 kernel: do_syscall_64+0x80/0x160 kernel: ?
    syscall_exit_to_user_mode+0x82/0x240 kernel: ? do_syscall_64+0x8d/0x160 kernel: ?
    syscall_exit_to_user_mode+0x82/0x240 kernel: ? do_syscall_64+0x8d/0x160 kernel: ?
    exc_page_fault+0x69/0x150 kernel: entry_SYSCALL_64_after_hwframe+0x6e/0x76 kernel: RIP:
    0033:0x7ffbc0cb87c9 kernel: Code: 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 66 90 48 89 f8 48 89 f7 48
    89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 48 3d 01 f0 ff ff 73 01 c3 48 8b 0d 97 96 0d
    00 f7 d8 64 89 01 48 kernel: RSP: 002b:00007ffc29d2f388 EFLAGS: 00000206 ORIG_RAX: 00000000000001af
    kernel: RAX: fffffffffff ---truncated---(CVE-2024-26688)

    In the Linux kernel, the following vulnerability has been resolved: l2tp: pass correct message length to
    ip6_append_data l2tp_ip6_sendmsg needs to avoid accounting for the transport header twice when splicing
    more data into an already partially-occupied skbuff. To manage this, we check whether the skbuff contains
    data using skb_queue_empty when deciding how much data to append using ip6_append_data. However, the code
    which performed the calculation was incorrect: ulen = len + skb_queue_empty(sk-sk_write_queue) ?
    transhdrlen : 0; ...due to C operator precedence, this ends up setting ulen to transhdrlen for messages
    with a non-zero length, which results in corrupted packets on the wire. Add parentheses to correct the
    calculation in line with the original intent.(CVE-2024-26752)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_try_best_found() Determine if the group block bitmap is corrupted before using
    ac_b_ex in ext4_mb_try_best_found() to avoid allocating blocks from a group with a corrupted block bitmap
    in the following concurrency and making the situation worse. ext4_mb_regular_allocator ext4_lock_group(sb,
    group) ext4_mb_good_group // check if the group bbitmap is corrupted ext4_mb_complex_scan_group // Scan
    group gets ac_b_ex but doesn't use it ext4_unlock_group(sb, group) ext4_mark_group_bitmap_corrupted(group)
    // The block bitmap was corrupted during // the group unlock gap. ext4_mb_try_best_found
    ext4_lock_group(ac-ac_sb, group) ext4_mb_use_best_found mb_mark_used // Allocating blocks in block
    bitmap corrupted group(CVE-2024-26773)

    In the Linux kernel, the following vulnerability has been resolved: ALSA: sh: aica: reorder cleanup
    operations to avoid UAF bugs The dreamcastcard-timer could schedule the spu_dma_work and the
    spu_dma_work could also arm the dreamcastcard-timer. When the snd_pcm_substream is closing, the
    aica_channel will be deallocated. But it could still be dereferenced in the worker thread. The reason is
    that del_timer() will return directly regardless of whether the timer handler is running or not and the
    worker could be rescheduled in the timer handler. As a result, the UAF bug will happen. The racy situation
    is shown below: (Thread 1) | (Thread 2) snd_aicapcm_pcm_close() | ... | run_spu_dma() //worker |
    mod_timer() flush_work() | del_timer() | aica_period_elapsed() //timer kfree(dreamcastcard-channel) |
    schedule_work() | run_spu_dma() //worker ... | dreamcastcard-channel- //USE In order to mitigate
    this bug and other possible corner cases, call mod_timer() conditionally in run_spu_dma(), then implement
    PCM sync_stop op to cancel both the timer and worker. The sync_stop op will be called from PCM core
    appropriately when needed.(CVE-2024-26654)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_find_by_goal() Places the logic for checking if the group's block bitmap is
    corrupt under the protection of the group lock to avoid allocating blocks from the group with a corrupted
    block bitmap.(CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved: blk-mq: fix IO hang from sbitmap
    wakeup race In blk_mq_mark_tag_wait(), __add_wait_queue() may be re-ordered with the following
    blk_mq_get_driver_tag() in case of getting driver tag failure. Then in __sbitmap_queue_wake_up(),
    waitqueue_active() may not observe the added waiter in blk_mq_mark_tag_wait() and wake up nothing,
    meantime blk_mq_mark_tag_wait() can't get driver tag successfully. This issue can be reproduced by running
    the following test in loop, and fio hang can be observed in  30min when running it on my test VM in
    laptop. modprobe -r scsi_debug modprobe scsi_debug delay=0 dev_size_mb=4096 max_queue=1 host_max_queue=1
    submit_queues=4 dev=`ls -d /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*/block/* | head -1 |
    xargs basename` fio --filename=/dev/'$dev' --direct=1 --rw=randrw --bs=4k --iodepth=1 \ --runtime=100
    --numjobs=40 --time_based --name=test \ --ioengine=libaio Fix the issue by adding one explicit barrier in
    blk_mq_mark_tag_wait(), which is just fine in case of running out of tag.(CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved: net: atlantic: Fix DMA mapping for PTP
    hwts ring Function aq_ring_hwts_rx_alloc() maps extra AQ_CFG_RXDS_DEF bytes for PTP HWTS ring but then
    generic aq_ring_free() does not take this into account. Create and use a specific function to free HWTS
    ring to fix this issue.(CVE-2024-26680)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: sr: fix possible use-after-free
    and null-ptr-deref The pernet operations structure for the subsystem must be registered before registering
    the generic netlink family.(CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved: HID: logitech-hidpp: Fix kernel crash
    on receiver USB disconnect hidpp_connect_event() has *four* time-of-check vs time-of-use (TOCTOU) races
    when it races with itself. hidpp_connect_event() primarily runs from a workqueue but it also runs on
    probe() and if a 'device-connected' packet is received by the hw when the thread running
    hidpp_connect_event() from probe() is waiting on the hw, then a second thread running
    hidpp_connect_event() will be started from the workqueue.(CVE-2023-52478)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted. This results in a memory leak [1] which can be
    reproduced using [2]. Fix by introducing a 'tmplt_reoffload' operation and have the stack invoke it with
    the appropriate arguments as part of the replay. Implement the operation in the sole classifier that
    supports chain templates (flower) by emitting the 'FLOW_CLS_TMPLT_{CREATE,DESTROY}' command based on
    whether a flow offload callback is being bound to a filter block or being unbound from one. As far as I
    can tell, the issue happens since cited commit which reordered tcf_block_offload_unbind() before
    tcf_block_flush_all_chains() in __tcf_block_put(). The order cannot be reversed as the filter block is
    expected to be freed after flushing all the chains.(CVE-2024-26669)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: fix use-after-free bug The
    bug can be triggered by sending a single amdgpu_gem_userptr_ioctl to the AMDGPU DRM driver on any ASICs
    with an invalid address and size. The bug was reported by Joonkyo Jung joonkyoj@yonsei.ac.kr. For
    example the following code: static void Syzkaller1(int fd) { struct drm_amdgpu_gem_userptr arg; int ret;
    arg.addr = 0xffffffffffff0000; arg.size = 0x80000000; /*2 Gb*/ arg.flags = 0x7; ret = drmIoctl(fd,
    0xc1186451/*amdgpu_gem_userptr_ioctl*/, arg); } Due to the address and size are not valid there is a
    failure in amdgpu_hmm_register-mmu_interval_notifier_insert-__mmu_interval_notifier_insert-
    check_shl_overflow, but we even the amdgpu_hmm_register failure we still call amdgpu_hmm_unregister into
    amdgpu_gem_object_free which causes access to a bad address.(CVE-2024-26656)

    In the Linux kernel, the following vulnerability has been resolved:netfilter: nft_limit: reject
    configurations that cause integer overflow.Reject bogus configs where internal token counter wraps
    around.This only occurs with very very large requests, such as  17gbyte/s.Its better to reject this rather
    than having incorrect ratelimit.(CVE-2024-26668)

    In the Linux kernel, the following vulnerability has been resolved:inet: read sk-sk_family once in
    inet_recv_error().inet_recv_error() is called without holding the socket lock.IPv6 socket could mutate to
    IPv4 with IPV6_ADDRFORM.socket option and trigger a KCSAN warning.(CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved:drm/amd/display: Add NULL test for
    'timing generator' in 'dcn21_set_pipe()'.In 'u32 otg_inst = pipe_ctx-stream_res.tg-inst;'pipe_ctx-
    stream_res.tg could be NULL, it is relying on the caller to ensure the tg is not NULL.(CVE-2024-26661)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Support specifying the
    srpt_service_guid parameter Make loading ib_srpt with this parameter set work. The current behavior is
    that setting that parameter while loading the ib_srpt kernel module triggers the following kernel crash:
    BUG: kernel NULL pointer dereference, address: 0000000000000000 Call Trace: TASK
    parse_one+0x18c/0x1d0 parse_args+0xe1/0x230 load_module+0x8de/0xa60 init_module_from_file+0x8b/0xd0
    idempotent_init_module+0x181/0x240 __x64_sys_finit_module+0x5a/0xb0 do_syscall_64+0x5f/0xe0
    entry_SYSCALL_64_after_hwframe+0x6e/0x76(CVE-2024-26744)

    In the Linux kernel, the following vulnerability has been resolved: ceph: prevent use-after-free in
    encode_cap_msg() In fs/ceph/caps.c, in encode_cap_msg(), 'use after free' error was caught by KASAN at
    this line - 'ceph_buffer_get(arg-xattr_buf);'. This implies before the refcount could be increment
    here, it was freed. In same file, in 'handle_cap_grant()' refcount is decremented by this line -
    'ceph_buffer_put(ci-i_xattrs.blob);'. It appears that a race occurred and resource was freed by the
    latter line before the former line could increment it. encode_cap_msg() is called by __send_cap() and
    __send_cap() is called by ceph_check_caps() after calling __prep_cap(). __prep_cap() is where arg-
    xattr_buf is assigned to ci-i_xattrs.blob. This is the spot where the refcount must be increased to
    prevent 'use after free' error.(CVE-2024-26689)

    In the Linux kernel, the following vulnerability has been resolved: mm/swap: fix race when skipping
    swapcache When skipping swapcache for SWP_SYNCHRONOUS_IO, if two or more threads swapin the same entry at
    the same time, they get different pages (A, B). Before one thread (T0) finishes the swapin and installs
    page (A) to the PTE, another thread (T1) could finish swapin of page (B), swap_free the entry, then swap
    out the possibly modified page reusing the same entry. It breaks the pte_same check in (T0) because PTE
    value is unchanged, causing ABA problem. Thread (T0) will install a stalled page (A) into the PTE and
    cause data corruption. One possible callstack is like this: CPU0 CPU1 ---- ---- do_swap_page()
    do_swap_page() with same entry direct swapin path direct swapin path alloc page A
    alloc page B swap_read_folio() - read to page A swap_read_folio() - read to page B slow on
    later locks or interrupt finished swapin first ... set_pte_at() swap_free() - entry is free
    write to page B, now page A stalled swap out page B to same swap entry pte_same() - Check
    pass, PTE seems unchanged, but page A is stalled! swap_free() - page B content lost! set_pte_at() -
    staled page A installed! And besides, for ZRAM, swap_free() allows the swap device to discard the entry
    content, so even if page (B) is not modified, if swap_read_folio() on CPU0 happens later than swap_free()
    on CPU1, it may also cause data loss. To fix this, reuse swapcache_prepare which will pin the swap entry
    using the cache flag, and allow only one thread to swap it in, also prevent any parallel code from putting
    the entry in the cache. Release the pin after PT unlocked. Racers just loop and wait since it's a rare and
    very short event. A schedule_timeout_uninterruptible(1) call is added to avoid repeated page faults
    wasting too much CPU, causing livelock or adding too much noise to perf statistics. A similar livelock
    issue was described in commit 029c4628b2eb ('mm: swap: get rid of livelock in swapin readahead')
    Reproducer: This race issue can be triggered easily using a well constructed reproducer and patched brd
    (with a delay in read path) [1]: With latest 6.8 mainline, race caused data loss can be observed easily: $
    gcc -g -lpthread test-thread-swap-race.c  ./a.out Polulating 32MB of memory region... Keep swapping
    out... Starting round 0... Spawning 65536 workers... 32746 workers spawned, wait for done... Round 0:
    Error on 0x5aa00, expected 32746, got 32743, 3 data loss! Round 0: Error on 0x395200, expected 32746, got
    32743, 3 data loss! Round 0: Error on 0x3fd000, expected 32746, got 32737, 9 data loss! Round 0 Failed, 15
    data loss! This reproducer spawns multiple threads sharing the same memory region using a small swap
    device. Every two threads updates mapped pages one by one in opposite direction trying to create a race,
    with one dedicated thread keep swapping out the data out using madvise. The reproducer created a reproduce
    rate of about once every 5 minutes, so the race should be totally possible in production. After this
    patch, I ran the reproducer for over a few hundred rounds and no data loss observed. Performance overhead
    is minimal, microbenchmark swapin 10G from 32G zram: Before: 10934698 us After: 11157121 us Cached:
    13155355 us (Dropping SWP_SYNCHRONOUS_IO flag) [kasong@tencent.com: v4] Link:
    https://lkml.kernel.org/r/20240219082040.7495-1-ryncsn@gmail.com(CVE-2024-26759)

    In the Linux kernel, the following vulnerability has been resolved: mm/writeback: fix possible divide-by-
    zero in wb_dirty_limits(), again (struct dirty_throttle_control *)-thresh is an unsigned long, but is
    passed as the u32 divisor argument to div_u64(). On architectures where unsigned long is 64 bytes, the
    argument will be implicitly truncated. Use div64_u64() instead of div_u64() so that the value used in the
    'is this a safe division' check is the same as the divisor. Also, remove redundant cast of the numerator
    to u64, as that should happen implicitly. This would be difficult to exploit in memcg domain, given the
    ratio-based arithmetic domain_drity_limits() uses, but is much easier in global writeback domain with a
    BDI_CAP_STRICTLIMIT-backing device, using e.g. vm.dirty_bytes=(132)*PAGE_SIZE so that dtc-thresh
    == (132)(CVE-2024-26720)

    In the Linux kernel, the following vulnerability has been resolved: usb: roles: fix NULL pointer issue
    when put module's reference In current design, usb role class driver will get usb_role_switch parent's
    module reference after the user get usb_role_switch device and put the reference after the user put the
    usb_role_switch device. However, the parent device of usb_role_switch may be removed before the user put
    the usb_role_switch. If so, then, NULL pointer issue will be met when the user put the parent module's
    reference. This will save the module pointer in structure of usb_role_switch. Then, we don't need to find
    module by iterating long relations.(CVE-2024-26747)

    In the Linux kernel, the following vulnerability has been resolved: asix: fix uninit-value in
    asix_mdio_read() asix_read_cmd() may read less than sizeof(smsr) bytes and in this case smsr will be
    uninitialized.(CVE-2021-47101)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/qedr: Fix qedr_create_user_qp
    error flow Avoid the following warning by making sure to free the allocated resources in case that
    qedr_init_user_queue() fail. -----------[ cut here ]----------- WARNING: CPU: 0 PID: 143192 at
    drivers/infiniband/core/rdma_core.c:874 uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs] Modules linked in:
    tls target_core_user uio target_core_pscsi target_core_file target_core_iblock ib_srpt ib_srp
    scsi_transport_srp nfsd nfs_acl rpcsec_gss_krb5 auth_rpcgss nfsv4 dns_resolver nfs lockd grace fscache
    netfs 8021q garp mrp stp llc ext4 mbcache jbd2 opa_vnic ib_umad ib_ipoib sunrpc rdma_ucm ib_isert
    iscsi_target_mod target_core_mod ib_iser libiscsi scsi_transport_iscsi rdma_cm iw_cm ib_cm hfi1
    intel_rapl_msr intel_rapl_common mgag200 qedr sb_edac drm_shmem_helper rdmavt x86_pkg_temp_thermal
    drm_kms_helper intel_powerclamp ib_uverbs coretemp i2c_algo_bit kvm_intel dell_wmi_descriptor ipmi_ssif
    sparse_keymap kvm ib_core rfkill syscopyarea sysfillrect video sysimgblt irqbypass ipmi_si ipmi_devintf
    fb_sys_fops rapl iTCO_wdt mxm_wmi iTCO_vendor_support intel_cstate pcspkr dcdbas intel_uncore
    ipmi_msghandler lpc_ich acpi_power_meter mei_me mei fuse drm xfs libcrc32c qede sd_mod ahci libahci t10_pi
    sg crct10dif_pclmul crc32_pclmul crc32c_intel qed libata tg3 ghash_clmulni_intel megaraid_sas crc8 wmi
    [last unloaded: ib_srpt](CVE-2024-26743)

    In the Linux kernel, the following vulnerability has been resolved: tunnels: fix out of bounds access when
    building IPv6 PMTU error If the ICMPv6 error is built from a non-linear skb we get the following splat,
    BUG: KASAN: slab-out-of-bounds in do_csum+0x220/0x240 Read of size 4 at addr ffff88811d402c80 by task
    netperf/820 CPU: 0 PID: 820 Comm: netperf Not tainted 6.8.0-rc1+ #543 ... kasan_report+0xd8/0x110
    do_csum+0x220/0x240 csum_partial+0xc/0x20 skb_tunnel_check_pmtu+0xeb9/0x3280 vxlan_xmit_one+0x14c2/0x4080
    vxlan_xmit+0xf61/0x5c00 dev_hard_start_xmit+0xfb/0x510 __dev_queue_xmit+0x7cd/0x32a0
    br_dev_queue_push_xmit+0x39d/0x6a0 Use skb_checksum instead of csum_partial who cannot deal with non-
    linear SKBs.(CVE-2024-26665)

    In the Linux kernel, the following vulnerability has been resolved: netlink: Fix kernel-infoleak-after-
    free in __skb_datagram_iter syzbot reported the following uninit-value access issue [1]:
    netlink_to_full_skb() creates a new `skb` and puts the `skb-data` passed as a 1st arg of
    netlink_to_full_skb() onto new `skb`. The data size is specified as `len` and passed to skb_put_data().
    This `len` is based on `skb-end` that is not data offset but buffer offset. The `skb-end` contains
    data and tailroom. Since the tailroom is not initialized when the new `skb` created, KMSAN detects
    uninitialized memory area when copying the data. This patch resolved this issue by correct the len from
    `skb-end` to `skb-len`, which is the actual data offset.(CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved: hv_netvsc: Fix race condition between
    netvsc_probe and netvsc_remove In commit ac5047671758 ('hv_netvsc: Disable NAPI before closing the VMBus
    channel'), napi_disable was getting called for all channels, including all subchannels without confirming
    if they are enabled or not. This caused hv_netvsc getting hung at napi_disable, when netvsc_probe() has
    finished running but nvdev-subchan_work has not started yet. netvsc_subchan_work() -
    rndis_set_subchannel() has not created the sub-channels and because of that netvsc_sc_open() is not
    running. netvsc_remove() calls cancel_work_sync(nvdev-subchan_work), for which netvsc_subchan_work
    did not run. netif_napi_add() sets the bit NAPI_STATE_SCHED because it ensures NAPI cannot be scheduled.
    Then netvsc_sc_open() - napi_enable will clear the NAPIF_STATE_SCHED bit, so it can be scheduled.
    napi_disable() does the opposite. Now during netvsc_device_remove(), when napi_disable is called for those
    subchannels, napi_disable gets stuck on infinite msleep. This fix addresses this problem by ensuring that
    napi_disable() is not getting called for non-enabled NAPI struct. But netif_napi_del() is still necessary
    for these non-enabled NAPI struct for cleanup purpose.(CVE-2024-26698)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_pipapo: release
    elements in clone only from destroy path Clone already always provides a current view of the lookup table,
    use it to destroy the set, otherwise it is possible to destroy elements twice. This fix requires:
    212ed75dc5fb ('netfilter: nf_tables: integrate pipapo into commit protocol') which came after:
    9827a0e6e23b ('netfilter: nft_set_pipapo: release elements in clone from abort path').(CVE-2024-26809)

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

    In the Linux kernel, the following vulnerability has been resolved: ext4: fix double-free of blocks due to
    wrong extents moved_len In ext4_move_extents(), moved_len is only updated when all moves are successfully
    executed, and only discards orig_inode and donor_inode preallocations when moved_len is not zero. When the
    loop fails to exit after successfully moving some extents, moved_len is not updated and remains at 0, so
    it does not discard the preallocations. If the moved extents overlap with the preallocated extents, the
    overlapped extents are freed twice in ext4_mb_release_inode_pa() and ext4_process_freed_data() (as
    described in commit 94d7c16cbbbd ('ext4: Fix double-free of blocks with EXT4_IOC_MOVE_EXT')), and bb_free
    is incremented twice. Hence when trim is executed, a zero-division bug is triggered in
    mb_update_avg_fragment_size() because bb_free is not zero and bb_fragments is zero. Therefore, update
    move_len after each extent move to avoid the issue.(CVE-2024-26704)

    In the Linux kernel, the following vulnerability has been resolved: mmc: mmci: stm32: fix DMA API
    overlapping mappings warning Turning on CONFIG_DMA_API_DEBUG_SG results in the following warning: DMA-API:
    mmci-pl18x 48220000.mmc: cacheline tracking EEXIST, overlapping mappings aren't supported WARNING: CPU: 1
    PID: 51 at kernel/dma/debug.c:568 add_dma_entry+0x234/0x2f4 Modules linked in: CPU: 1 PID: 51 Comm:
    kworker/1:2 Not tainted 6.1.28 #1 Hardware name: STMicroelectronics STM32MP257F-EV1 Evaluation Board (DT)
    Workqueue: events_freezable mmc_rescan Call trace: add_dma_entry+0x234/0x2f4 debug_dma_map_sg+0x198/0x350
    __dma_map_sg_attrs+0xa0/0x110 dma_map_sg_attrs+0x10/0x2c sdmmc_idma_prep_data+0x80/0xc0
    mmci_prep_data+0x38/0x84 mmci_start_data+0x108/0x2dc mmci_request+0xe4/0x190
    __mmc_start_request+0x68/0x140 mmc_start_request+0x94/0xc0 mmc_wait_for_req+0x70/0x100
    mmc_send_tuning+0x108/0x1ac sdmmc_execute_tuning+0x14c/0x210 mmc_execute_tuning+0x48/0xec
    mmc_sd_init_uhs_card.part.0+0x208/0x464 mmc_sd_init_card+0x318/0x89c mmc_attach_sd+0xe4/0x180
    mmc_rescan+0x244/0x320 DMA API debug brings to light leaking dma-mappings as dma_map_sg and dma_unmap_sg
    are not correctly balanced. If an error occurs in mmci_cmd_irq function, only mmci_dma_error function is
    called and as this API is not managed on stm32 variant, dma_unmap_sg is never called in this error
    path.(CVE-2024-26787)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: prevent perpetual
    headroom growth syzkaller triggered following kasan splat: BUG: KASAN: use-after-free in
    __skb_flow_dissect(CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Lock external INTx masking
    ops Mask operations through config space changes to DisINTx may race INTx configuration changes via ioctl.
    Create wrappers that add locking for paths outside of the core interrupt code. In particular, irq_type is
    updated holding igate, therefore testing is_intx() requires holding igate. For example clearing DisINTx
    from config space can otherwise race changes of the interrupt configuration. This aligns interfaces which
    may trigger the INTx eventfd into two camps, one side serialized by igate and the other only enabled while
    INTx is configured. A subsequent patch introduces synchronization for the latter flows.(CVE-2024-26810)

    In the Linux kernel, the following vulnerability has been resolved: fs/aio: Restrict kiocb_set_cancel_fn()
    to I/O submitted via libaio If kiocb_set_cancel_fn() is called for I/O submitted via io_uring, the
    following kernel warning appears: WARNING: CPU: 3 PID: 368 at fs/aio.c:598 kiocb_set_cancel_fn+0x9c/0xa8
    Call trace: kiocb_set_cancel_fn+0x9c/0xa8 ffs_epfile_read_iter+0x144/0x1d0 io_read+0x19c/0x498
    io_issue_sqe+0x118/0x27c io_submit_sqes+0x25c/0x5fc __arm64_sys_io_uring_enter+0x104/0xab0
    invoke_syscall+0x58/0x11c el0_svc_common+0xb4/0xf4 do_el0_svc+0x2c/0xb0 el0_svc+0x2c/0xa4
    el0t_64_sync_handler+0x68/0xb4 el0t_64_sync+0x1a4/0x1a8 Fix this by setting the IOCB_AIO_RW flag for read
    and write I/O that is submitted by libaio.(CVE-2024-26764)

    In the Linux kernel, the following vulnerability has been resolved: xhci: handle isoc Babble and Buffer
    Overrun events properly xHCI 4.9 explicitly forbids assuming that the xHC has released its ownership of a
    multi-TRB TD when it reports an error on one of the early TRBs. Yet the driver makes such assumption and
    releases the TD, allowing the remaining TRBs to be freed or overwritten by new TDs. The xHC should also
    report completion of the final TRB due to its IOC flag being set by us, regardless of prior errors. This
    event cannot be recognized if the TD has already been freed earlier, resulting in 'Transfer event TRB DMA
    ptr not part of current TD' error message. Fix this by reusing the logic for processing isoc Transaction
    Errors. This also handles hosts which fail to report the final completion. Fix transfer length reporting
    on Babble errors. They may be caused by device malfunction, no guarantee that the buffer has been
    filled.(CVE-2024-26659)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Disable auto-enable of
    exclusive INTx IRQ Currently for devices requiring masking at the irqchip for INTx, ie. devices without
    DisINTx support, the IRQ is enabled in request_irq() and subsequently disabled as necessary to align with
    the masked status flag. This presents a window where the interrupt could fire between these events,
    resulting in the IRQ incrementing the disable depth twice. This would be unrecoverable for a user since
    the masked flag prevents nested enables through vfio. Instead, invert the logic using IRQF_NO_AUTOEN such
    that exclusive INTx is never auto-enabled, then unmask as required.(CVE-2024-27437)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: don't override
    retval if we already lost the skb If we're redirecting the skb, and haven't called tcf_mirred_forward(),
    yet, we need to tell the core to drop the skb by setting the retcode to SHOT. If we have called
    tcf_mirred_forward(), however, the skb is out of our hands and returning SHOT will lead to UaF. Move the
    retval override to the error path which actually need it.(CVE-2024-26739)

    In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in
    arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued,
    arp_req_get() looks up an neighbour entry and copies neigh-ha to struct arpreq.arp_ha.sa_data. The
    arp_ha here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In
    the splat below, 2 bytes are overflown to the next int field, arp_flags. We initialise the field just
    after the memcpy(), so it's not a problem. However, when dev-addr_len is greater than 22 (e.g.
    MAX_ADDR_LEN), arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL) in arp_ioctl() before
    calling arp_req_get(). To avoid the overflow, let's limit the max length of memcpy(). Note that commit
    b5f0de6df6dc ('net: dev: Convert sa_data to flexible array in struct sockaddr') just silenced
    syzkaller.(CVE-2024-26733)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Update error handler for
    UCTX and UMEM In the fast unload flow, the device state is set to internal error, which indicates that the
    driver started the destroy process. In this case, when a destroy command is being executed, it should
    return MLX5_CMD_STAT_OK. Fix MLX5_CMD_OP_DESTROY_UCTX and MLX5_CMD_OP_DESTROY_UMEM to return OK instead of
    EIO.(CVE-2021-47212)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix scsi_mode_sense()
    buffer length handling Several problems exist with scsi_mode_sense() buffer length handling: 1) The
    allocation length field of the MODE SENSE(10) command is 16-bits, occupying bytes 7 and 8 of the CDB. With
    this command, access to mode pages larger than 255 bytes is thus possible. However, the CDB allocation
    length field is set by assigning len to byte 8 only, thus truncating buffer length larger than 255. 2) If
    scsi_mode_sense() is called with len smaller than 8 with sdev-use_10_for_ms set, or smaller than 4
    otherwise, the buffer length is increased to 8 and 4 respectively, and the buffer is zero filled with
    these increased values, thus corrupting the memory following the buffer. Fix these 2 problems by using
    put_unaligned_be16() to set the allocation length field of MODE SENSE(10) CDB and by returning an error
    when len is too small.(CVE-2021-47182)

    In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage
    warning I received the following warning while running cthon against an ontap server running pNFS: [
    57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523]
    6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525]
    net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that
    might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks
    held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted
    6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536] Call Trace: [ 57.202537] TASK [
    57.202540] dump_stack_lvl+0x77/0xb0 [ 57.202551] lockdep_rcu_suspicious+0x154/0x1a0 [ 57.202556]
    rpc_xprt_switch_has_addr+0x17c/0x190 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202596]
    rpc_clnt_setup_test_and_add_xprt+0x50/0x180 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202621]
    ? rpc_clnt_add_xprt+0x254/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202646]
    rpc_clnt_add_xprt+0x27a/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202671] ?
    __pfx_rpc_clnt_setup_test_and_add_xprt+0x10/0x10 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [
    57.202696] nfs4_pnfs_ds_connect+0x345/0x760 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202728]
    ? __pfx_nfs4_test_session_trunk+0x10/0x10 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202754]
    nfs4_fl_prepare_ds+0x75/0xc0 [nfs_layout_nfsv41_files e3a4187f18ae8a27b630f9feae6831b584a9360a] [
    57.202760] filelayout_write_pagelist+0x4a/0x200 [nfs_layout_nfsv41_files
    e3a4187f18ae8a27b630f9feae6831b584a9360a] [ 57.202765] pnfs_generic_pg_writepages+0xbe/0x230 [nfsv4
    c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202788] __nfs_pageio_add_request+0x3fd/0x520 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202813] nfs_pageio_add_request+0x18b/0x390 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202831] nfs_do_writepage+0x116/0x1e0 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202849] nfs_writepages_callback+0x13/0x30 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202866] write_cache_pages+0x265/0x450 [ 57.202870] ?
    __pfx_nfs_writepages_callback+0x10/0x10 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202891]
    nfs_writepages+0x141/0x230 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202913]
    do_writepages+0xd2/0x230 [ 57.202917] ? filemap_fdatawrite_wbc+0x5c/0x80 [ 57.202921]
    filemap_fdatawrite_wbc+0x67/0x80 [ 57.202924] filemap_write_and_wait_range+0xd9/0x170 [ 57.202930]
    nfs_wb_all+0x49/0x180 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202947]
    nfs4_file_flush+0x72/0xb0 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202969]
    __se_sys_close+0x46/0xd0 [ 57.202972] do_syscall_64+0x68/0x100 [ 57.202975] ? do_syscall_64+0x77/0x100 [
    57.202976] ? do_syscall_64+0x77/0x100 [ 57.202979] entry_SYSCALL_64_after_hwframe+0x6e/0x76 [ 57.202982]
    RIP: 0033:0x7fe2b12e4a94 [ 57.202985] Code: 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00
    90 f3 0f 1e fa 80 3d d5 18 0e 00 00 74 13 b8 03 00 00 00 0f 05 48 3d 00 f0 ff ff 77 44 c3 0f 1f 00
    48 83 ec 18 89 7c 24 0c e8 c3 [ 57.202987] RSP: 002b:00007ffe857ddb38 EFLAGS: 00000202 ORIG_RAX:
    0000000000000003 [ 57.202989] RAX: ffffffffffffffda RBX: 00007ffe857dfd68 RCX: 00007fe2b12e4a94 [
    57.202991] RDX: 0000000000002000 RSI: 00007ffe857ddc40 RDI: 0000000000000003 [ 57.202992] RBP:
    00007ffe857dfc50 R08: 7fffffffffffffff R09: 0000000065650f49 [ 57.202993] R10: 00007f
    ---truncated---(CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved: dm-crypt: don't modify the data when
    using authenticated encryption It was said that authenticated encryption could produce invalid tag when
    the data that is being encrypted is modified [1]. So, fix this problem by copying the data into the clone
    bio first and then encrypt them inside the clone bio. This may reduce performance, but it is needed to
    prevent the user from corrupting the device by writing data with O_DIRECT and modifying them at the same
    time. [1] https://lore.kernel.org/all/20240207004723.GA35324@sol.localdomain/T/(CVE-2024-26763)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_chain_filter: handle
    NETDEV_UNREGISTER for inet/ingress basechain Remove netdevice from inet/ingress basechain in case
    NETDEV_UNREGISTER event is reported, otherwise a stale reference to netdevice remains in the hook
    list.(CVE-2024-26808)

    In the Linux kernel, the following vulnerability has been resolved: dmaengine: fix NULL pointer in channel
    unregistration function __dma_async_device_channel_register() can fail. In case of failure, chan-local
    is freed (with free_percpu()), and chan-local is nullified. When dma_async_device_unregister() is
    called (because of managed API or intentionally by DMA controller driver), channels are unconditionally
    unregistered, leading to this NULL pointer: [ 1.318693] Unable to handle kernel NULL pointer dereference
    at virtual address 00000000000000d0 [...] [ 1.484499] Call trace: [ 1.486930] device_del+0x40/0x394 [
    1.490314] device_unregister+0x20/0x7c [ 1.494220] __dma_async_device_channel_unregister+0x68/0xc0 Look at
    dma_async_device_register() function error path, channel device unregistration is done only if chan-
    local is not NULL. Then add the same condition at the beginning of
    __dma_async_device_channel_unregister() function, to avoid NULL pointer issue whatever the API used to
    reach this function.(CVE-2023-52492)
    In the Linux kernel, the following vulnerability has been resolved: ppp_async: limit MRU to 64K syzbot
    triggered a warning.(CVE-2024-26675)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: fix NEXTHDR_FRAGMENT
    handling in ip6_tnl_parse_tlv_enc_lim() syzbot pointed out(CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved: mfd: syscon: Fix null pointer
    dereference in of_syscon_register() kasprintf() returns a pointer to dynamically allocated memory which
    can be NULL upon failure.(CVE-2023-52467)

    In the Linux kernel, the following vulnerability has been resolved: tipc: Check the bearer type before
    calling tipc_udp_nl_bearer_add() syzbot reported the following general protection fault.(CVE-2024-26663)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_ct: sanitize layer 3
    and 4 protocol number in custom expectations - Disallow families other than NFPROTO_{IPV4,IPV6,INET}. -
    Disallow layer 4 protocol with no ports, since destination port is a mandatory attribute for this
    object.(CVE-2024-26673)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-fc: avoid deadlock on delete
    association path When deleting an association the shutdown path is deadlocking because we try to flush the
    nvmet_wq nested. Avoid this by deadlock by deferring the put work into its own work item.(CVE-2024-26769)

    In the Linux kernel, the following vulnerability has been resolved: devlink: fix possible use-after-free
    and memory leaks in devlink_init() The pernet operations structure for the subsystem must be registered
    before registering the generic netlink family. Make an unregister in case of unsuccessful
    registration.(CVE-2024-26734)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix DEVMAP_HASH overflow check on
    32-bit arches The devmap code allocates a number hash buckets equal to the next power of two of the
    max_entries value provided when creating the map. When rounding up to the next power of two, the 32-bit
    variable storing the number of buckets can overflow, and the code checks for overflow by checking if the
    truncated 32-bit value is equal to 0. However, on 32-bit arches the rounding up itself can overflow mid-
    way through, because it ends up doing a left-shift of 32 bits on an unsigned long value. If the size of an
    unsigned long is four bytes, this is undefined behaviour, so there is no guarantee that we'll end up with
    a nice and tidy 0-value at the end. Syzbot managed to turn this into a crash on arm32 by creating a
    DEVMAP_HASH with max_entries  0x80000000 and then trying to update it. Fix this by moving the overflow
    check to before the rounding up operation.(CVE-2024-26885)

    In the Linux kernel, the following vulnerability has been resolved: tracing/trigger: Fix to return error
    if failed to alloc snapshot Fix register_snapshot_trigger() to return error code if it failed to allocate
    a snapshot instead of 0 (success). Unless that, it will register snapshot trigger without an
    error.(CVE-2024-26920)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix hashtab overflow check on
    32-bit arches The hashtab code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. So apply the same fix to hashtab, by
    moving the overflow check to before the roundup.(CVE-2024-26884)

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

    In the Linux kernel, the following vulnerability has been resolved: fs/proc: do_task_stat: use sig-
    stats_lock to gather the threads/children stats lock_task_sighand() can trigger a hard lockup. If
    NR_CPUS threads call do_task_stat() at the same time and the process has NR_THREADS, it will spin with
    irqs disabled O(NR_CPUS * NR_THREADS) time. Change do_task_stat() to use sig-stats_lock to gather the
    statistics outside of -siglock protected section, in the likely case this code will run
    lockless.(CVE-2024-26686)

    In the Linux kernel, the following vulnerability has been resolved: ice: xsk: return xsk buffers back to
    pool when cleaning the ring Currently we only NULL the xdp_buff pointer in the internal SW ring but we
    never give it back to the xsk buffer pool. This means that buffers can be leaked out of the buff pool and
    never be used again. Add missing xsk_buff_free() call to the routine that is supposed to clean the entries
    that are left in the ring so that these buffers in the umem can be used by other sockets. Also, only go
    through the space that is actually left to be cleaned instead of a whole ring.(CVE-2021-47105)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: make sure to pull inner
    header in __ip6_tnl_rcv() syzbot found __ip6_tnl_rcv() could access unitiliazed data [1]. Call
    pskb_inet_may_pull() to fix this, and initialize ipv6h variable after this call as it can change skb-
    head.(CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix stackmap overflow check on
    32-bit arches The stackmap code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. The commit in the fixes tag actually
    attempted to fix this, but the fix did not account for the UB, so the fix only works on CPUs where an
    overflow does result in a neat truncation to zero, which is not guaranteed. Checking the value before
    rounding does not have this problem.(CVE-2024-26883)

    In the Linux kernel, the following vulnerability has been resolved: crypto: ccp - Fix null pointer
    dereference in __sev_platform_shutdown_locked The SEV platform device can be shutdown with a null
    psp_master, e.g., using DEBUG_TEST_DRIVER_REMOVE.(CVE-2024-26695)

    In the Linux kernel, the following vulnerability has been resolved: md: fix kmemleak of rdev-serial If
    kobject_add() is fail in bind_rdev_to_array(), 'rdev-serial' will be alloc not be freed, and kmemleak
    occurs. unreferenced object 0xffff88815a350000 (size 49152): comm 'mdadm', pid 789, jiffies 4294716910 hex
    dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc f773277a): [0000000058b0a453]
    kmemleak_alloc+0x61/0xe0 [00000000366adf14] __kmalloc_large_node+0x15e/0x270
    [000000002e82961b] __kmalloc_node.cold+0x11/0x7f [00000000f206d60a] kvmalloc_node+0x74/0x150
    [0000000034bf3363] rdev_init_serial+0x67/0x170 [0000000010e08fe9]
    mddev_create_serial_pool+0x62/0x220 [00000000c3837bf0] bind_rdev_to_array+0x2af/0x630
    [0000000073c28560] md_add_new_disk+0x400/0x9f0 [00000000770e30ff] md_ioctl+0x15bf/0x1c10
    [000000006cfab718] blkdev_ioctl+0x191/0x3f0 [0000000085086a11] vfs_ioctl+0x22/0x60
    [0000000018b656fe] __x64_sys_ioctl+0xba/0xe0 [00000000e54e675e] do_syscall_64+0x71/0x150
    [000000008b0ad622] entry_SYSCALL_64_after_hwframe+0x6c/0x74(CVE-2024-26900)

    In the Linux kernel, the following vulnerability has been resolved: net: ice: Fix potential NULL pointer
    dereference in ice_bridge_setlink() The function ice_bridge_setlink() may encounter a NULL pointer
    dereference if nlmsg_find_attr() returns NULL and br_spec is dereferenced subsequently in
    nla_for_each_nested(). To address this issue, add a check to ensure that br_spec is not NULL before
    proceeding with the nested attribute iteration.(CVE-2024-26855)

    In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix memory leak in
    cachefiles_add_cache() The following memory leak was reported after unbinding /dev/cachefiles:
    ================================================================== unreferenced object 0xffff9b674176e3c0
    (size 192): comm 'cachefilesd2', pid 680, jiffies 4294881224 hex dump (first 32 bytes): 01 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ................ backtrace (crc ea38a44b): [ffffffff8eb8a1a5] kmem_cache_alloc+0x2d5/0x370
    [ffffffff8e917f86] prepare_creds+0x26/0x2e0 [ffffffffc002eeef]
    cachefiles_determine_cache_security+0x1f/0x120 [ffffffffc00243ec] cachefiles_add_cache+0x13c/0x3a0
    [ffffffffc0025216] cachefiles_daemon_write+0x146/0x1c0 [ffffffff8ebc4a3b] vfs_write+0xcb/0x520
    [ffffffff8ebc5069] ksys_write+0x69/0xf0 [ffffffff8f6d4662] do_syscall_64+0x72/0x140
    [ffffffff8f8000aa] entry_SYSCALL_64_after_hwframe+0x6e/0x76
    ================================================================== Put the reference count of cache_cred
    in cachefiles_daemon_unbind() to fix the problem. And also put cache_cred in cachefiles_add_cache() error
    branch to avoid memory leaks.(CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved: do_sys_name_to_handle(): use kzalloc()
    to fix kernel-infoleak syzbot identified a kernel information leak vulnerability in
    do_sys_name_to_handle() and issued the following report [1]. [1] 'BUG: KMSAN: kernel-infoleak in
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
    0000000020000240' Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to solve the
    problem.(CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: processor_idle: Fix memory leak
    in acpi_processor_power_exit() After unregistering the CPU idle device, the memory associated with it is
    not freed, leading to a memory leak: unreferenced object 0xffff896282f6c000 (size 1024): comm 'swapper/0',
    pid 1, jiffies 4294893170 hex dump (first 32 bytes): 00 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00
    ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc
    8836a742): [ffffffff993495ed] kmalloc_trace+0x29d/0x340 [ffffffff9972f3b3]
    acpi_processor_power_init+0xf3/0x1c0 [ffffffff9972d263] __acpi_processor_start+0xd3/0xf0
    [ffffffff9972d2bc] acpi_processor_start+0x2c/0x50 [ffffffff99805872] really_probe+0xe2/0x480
    [ffffffff99805c98] __driver_probe_device+0x78/0x160 [ffffffff99805daf]
    driver_probe_device+0x1f/0x90 [ffffffff9980601e] __driver_attach+0xce/0x1c0 [ffffffff99803170]
    bus_for_each_dev+0x70/0xc0 [ffffffff99804822] bus_add_driver+0x112/0x210 [ffffffff99807245]
    driver_register+0x55/0x100 [ffffffff9aee4acb] acpi_processor_driver_init+0x3b/0xc0
    [ffffffff990012d1] do_one_initcall+0x41/0x300 [ffffffff9ae7c4b0]
    kernel_init_freeable+0x320/0x470 [ffffffff99b231f6] kernel_init+0x16/0x1b0 [ffffffff99042e6d]
    ret_from_fork+0x2d/0x50 Fix this by freeing the CPU idle device after unregistering it.(CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Fix memory leak in
    dm_sw_fini() After destroying dmub_srv, the memory associated with it is not freed, causing a memory leak:
    unreferenced object 0xffff896302b45800 (size 1024): comm '(udev-worker)', pid 222, jiffies 4294894636 hex
    dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc 6265fd77): [ffffffff993495ed]
    kmalloc_trace+0x29d/0x340 [ffffffffc0ea4a94] dm_dmub_sw_init+0xb4/0x450 [amdgpu]
    [ffffffffc0ea4e55] dm_sw_init+0x15/0x2b0 [amdgpu] [ffffffffc0ba8557]
    amdgpu_device_init+0x1417/0x24e0 [amdgpu] [ffffffffc0bab285] amdgpu_driver_load_kms+0x15/0x190
    [amdgpu] [ffffffffc0ba09c7] amdgpu_pci_probe+0x187/0x4e0 [amdgpu] [ffffffff9968fd1e]
    local_pci_probe+0x3e/0x90 [ffffffff996918a3] pci_device_probe+0xc3/0x230 [ffffffff99805872]
    really_probe+0xe2/0x480 [ffffffff99805c98] __driver_probe_device+0x78/0x160 [ffffffff99805daf]
    driver_probe_device+0x1f/0x90 [ffffffff9980601e] __driver_attach+0xce/0x1c0 [ffffffff99803170]
    bus_for_each_dev+0x70/0xc0 [ffffffff99804822] bus_add_driver+0x112/0x210 [ffffffff99807245]
    driver_register+0x55/0x100 [ffffffff990012d1] do_one_initcall+0x41/0x300 Fix this by freeing
    dmub_srv after destroying it.(CVE-2024-26833)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Do not register event
    handler until srpt device is fully setup Upon rare occasions, KASAN reports a use-after-free Write in
    srpt_refresh_port(). This seems to be because an event handler is registered before the srpt device is
    fully setup and a race condition upon error may leave a partially setup event handler in place. Instead,
    only register the event handler after srpt device initialization is complete.(CVE-2024-26872)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix uaf in
    pvr2_context_set_notify [Syzbot reported] BUG: KASAN: slab-use-after-free in
    pvr2_context_set_notify+0x2c4/0x310 drivers/media/usb/pvrusb2/pvrusb2-context.c:35 Read of size 4 at addr
    ffff888113aeb0d8 by task kworker/1:1/26 CPU: 1 PID: 26 Comm: kworker/1:1 Not tainted
    6.8.0-rc1-syzkaller-00046-gf1a27f081c1f #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/25/2024 Workqueue: usb_hub_wq hub_event Call Trace: TASK __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0xd9/0x1b0 lib/dump_stack.c:106 print_address_description
    mm/kasan/report.c:377 [inline] print_report+0xc4/0x620 mm/kasan/report.c:488 kasan_report+0xda/0x110
    mm/kasan/report.c:601 pvr2_context_set_notify+0x2c4/0x310 drivers/media/usb/pvrusb2/pvrusb2-context.c:35
    pvr2_context_notify drivers/media/usb/pvrusb2/pvrusb2-context.c:95 [inline]
    pvr2_context_disconnect+0x94/0xb0 drivers/media/usb/pvrusb2/pvrusb2-context.c:272 Freed by task 906:
    kasan_save_stack+0x33/0x50 mm/kasan/common.c:47 kasan_save_track+0x14/0x30 mm/kasan/common.c:68
    kasan_save_free_info+0x3f/0x60 mm/kasan/generic.c:640 poison_slab_object mm/kasan/common.c:241 [inline]
    __kasan_slab_free+0x106/0x1b0 mm/kasan/common.c:257 kasan_slab_free include/linux/kasan.h:184 [inline]
    slab_free_hook mm/slub.c:2121 [inline] slab_free mm/slub.c:4299 [inline] kfree+0x105/0x340 mm/slub.c:4409
    pvr2_context_check drivers/media/usb/pvrusb2/pvrusb2-context.c:137 [inline]
    pvr2_context_thread_func+0x69d/0x960 drivers/media/usb/pvrusb2/pvrusb2-context.c:158 [Analyze] Task A set
    disconnect_flag = !0, which resulted in Task B's condition being met and releasing mp, leading to this
    issue. [Fix] Place the disconnect_flag assignment operation after all code in pvr2_context_disconnect() to
    avoid this issue.(CVE-2024-26875)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: set dormant flag
    on hook register failure We need to set the dormant flag again if we fail to register the hooks. During
    memory pressure hook registration can fail and we end up with a table marked as active but no registered
    hooks. On table/base chain deletion, nf_tables will attempt to unregister the hook again which yields a
    warn splat from the nftables core.(CVE-2024-26835)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_conntrack_h323: Add
    protection for bmp length out of range UBSAN load reports an exception of BRK#5515 SHIFT_ISSUE:Bitwise
    shifts that are out of bounds for their data type.(CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved: Bluetooth: hci_core: Fix possible
    buffer overflow struct hci_dev_info has a fixed size name[8] field so in the event that hdev-name is
    bigger than that strcpy would attempt to write past its size, so this fixes this problem by switching to
    use strscpy.(CVE-2024-26889)

    In the Linux kernel, the following vulnerability has been resolved: NFSv4.2: fix nfs4_listxattr kernel BUG
    at mm/usercopy.c:102 A call to listxattr() with a buffer size = 0 returns the actual size of the buffer
    needed for a subsequent call. When size  0, nfs4_listxattr() does not return an error because either
    generic_listxattr() or nfs4_listxattr_nfs4_label() consumes exactly all the bytes then size is 0 when
    calling nfs4_listxattr_nfs4_user() which then triggers the following kernel BUG: [ 99.403778] kernel BUG
    at mm/usercopy.c:102! [ 99.404063] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP [ 99.408463] CPU:
    0 PID: 3310 Comm: python3 Not tainted 6.6.0-61.fc40.aarch64 #1 [ 99.415827] Call trace: [ 99.415985]
    usercopy_abort+0x70/0xa0 [ 99.416227] __check_heap_object+0x134/0x158 [ 99.416505]
    check_heap_object+0x150/0x188 [ 99.416696] __check_object_size.part.0+0x78/0x168 [ 99.416886]
    __check_object_size+0x28/0x40 [ 99.417078] listxattr+0x8c/0x120 [ 99.417252] path_listxattr+0x78/0xe0 [
    99.417476] __arm64_sys_listxattr+0x28/0x40 [ 99.417723] invoke_syscall+0x78/0x100 [ 99.417929]
    el0_svc_common.constprop.0+0x48/0xf0 [ 99.418186] do_el0_svc+0x24/0x38 [ 99.418376] el0_svc+0x3c/0x110 [
    99.418554] el0t_64_sync_handler+0x120/0x130 [ 99.418788] el0t_64_sync+0x194/0x198 [ 99.418994] Code:
    aa0003e3 d000a3e0 91310000 97f49bdb (d4210000) Issue is reproduced when generic_listxattr() returns
    'system.nfs4_acl', thus calling lisxattr() with size = 16 will trigger the bug. Add check on
    nfs4_listxattr() to return ERANGE error when it is called with size  0 and the return value is greater
    than size.(CVE-2024-26870)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: make sure to pull
    inner header in ip_tunnel_rcv() Apply the same fix than ones found in : 8d975c15c0cd ('ip6_tunnel: make
    sure to pull inner header in __ip6_tnl_rcv()') 1ca1ba465e55 ('geneve: make sure to pull inner header in
    geneve_rx()') We have to save skb-network_header in a temporary variable in order to be able to
    recompute the network_header pointer after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure
    the needed headers are in skb-head.(CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved: packet: annotate data-races around
    ignore_outgoing ignore_outgoing is read locklessly from dev_queue_xmit_nit() and packet_getsockopt() Add
    appropriate READ_ONCE()/WRITE_ONCE() annotations.(CVE-2024-26862)

    In the Linux kernel, the following vulnerability has been resolved: net/bnx2x: Prevent access to a freed
    page in page_pool Fix race condition leading to system crash during EEH error handling During EEH error
    recovery, the bnx2x driver's transmit timeout logic could cause a race condition when handling reset
    tasks. The bnx2x_tx_timeout() schedules reset tasks via bnx2x_sp_rtnl_task(), which ultimately leads to
    bnx2x_nic_unload(). In bnx2x_nic_unload() SGEs are freed using bnx2x_free_rx_sge_range(). However, this
    could overlap with the EEH driver's attempt to reset the device using bnx2x_io_slot_reset(), which also
    tries to free SGEs. This race condition can result in system crashes due to accessing freed memory
    locations in bnx2x_free_rx_sge() 799 static inline void bnx2x_free_rx_sge(struct bnx2x *bp, 800 struct
    bnx2x_fastpath *fp, u16 index) 801 { 802 struct sw_rx_page *sw_buf = fp-rx_page_ring[index]; 803
    struct page *page = sw_buf-page; .... where sw_buf was set to NULL after the call to dma_unmap_page()
    by the preceding thread. EEH: Beginning: 'slot_reset' PCI 0011:01:00.0#10000: EEH: Invoking
    bnx2x-slot_reset() bnx2x: [bnx2x_io_slot_reset:14228(eth1)]IO slot reset initializing... bnx2x
    0011:01:00.0: enabling device (0140 - 0142) bnx2x: [bnx2x_io_slot_reset:14244(eth1)]IO slot reset --
    driver unload Kernel attempted to read user page (0) - exploit attempt? (uid: 0) BUG: Kernel NULL pointer
    dereference on read at 0x00000000 Faulting instruction address: 0xc0080000025065fc Oops: Kernel access of
    bad area, sig: 11 [#1] ..... Call Trace: [c000000003c67a20] [c00800000250658c]
    bnx2x_io_slot_reset+0x204/0x610 [bnx2x] (unreliable) [c000000003c67af0] [c0000000000518a8]
    eeh_report_reset+0xb8/0xf0 [c000000003c67b60] [c000000000052130] eeh_pe_report+0x180/0x550
    [c000000003c67c70] [c00000000005318c] eeh_handle_normal_event+0x84c/0xa60 [c000000003c67d50]
    [c000000000053a84] eeh_event_handler+0xf4/0x170 [c000000003c67da0] [c000000000194c58] kthread+0x1c8/0x1d0
    [c000000003c67e10] [c00000000000cf64] ret_from_kernel_thread+0x5c/0x64 To solve this issue, we need to
    verify page pool allocations before freeing.(CVE-2024-26859)

    A race condition was found in the Linux kernel's bluetooth device driver in {min,max}_key_size_set()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24860)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Check rcu_read_lock_trace_held()
    before calling bpf map helpers These three bpf_map_{lookup,update,delete}_elem() helpers are also
    available for sleepable bpf program, so add the corresponding lock assertion for sleepable bpf program,
    otherwise the following warning will be reported when a sleepable bpf program manipulates bpf map under
    interpreter mode (aka bpf_jit_enable=0): WARNING: CPU: 3 PID: 4985 at kernel/bpf/helpers.c:40 ...... CPU:
    3 PID: 4985 Comm: test_progs Not tainted 6.6.0+ #2 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)
    ...... RIP: 0010:bpf_map_lookup_elem+0x54/0x60 ...... Call Trace: TASK ? __warn+0xa5/0x240 ?
    bpf_map_lookup_elem+0x54/0x60 ? report_bug+0x1ba/0x1f0 ? handle_bug+0x40/0x80 ? exc_invalid_op+0x18/0x50 ?
    asm_exc_invalid_op+0x1b/0x20 ? __pfx_bpf_map_lookup_elem+0x10/0x10 ?
    rcu_lockdep_current_cpu_online+0x65/0xb0 ? rcu_is_watching+0x23/0x50 ? bpf_map_lookup_elem+0x54/0x60 ?
    __pfx_bpf_map_lookup_elem+0x10/0x10 ___bpf_prog_run+0x513/0x3b70 __bpf_prog_run32+0x9d/0xd0 ?
    __bpf_prog_enter_sleepable_recur+0xad/0x120 ? __bpf_prog_enter_sleepable_recur+0x3e/0x120
    bpf_trampoline_6442580665+0x4d/0x1000 __x64_sys_getpgid+0x5/0x30 ? do_syscall_64+0x36/0xb0
    entry_SYSCALL_64_after_hwframe+0x6e/0x76 /TASK(CVE-2023-52621)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1837
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb01684f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/25");

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
  "bpftool-5.10.0-60.18.0.50.h1358.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1358.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1358.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1358.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1358.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1358.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
