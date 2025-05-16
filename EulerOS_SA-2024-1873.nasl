#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201152);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2021-46918",
    "CVE-2021-47036",
    "CVE-2021-47037",
    "CVE-2021-47070",
    "CVE-2021-47076",
    "CVE-2023-52433",
    "CVE-2023-52434",
    "CVE-2023-52435",
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
    "CVE-2023-52476",
    "CVE-2023-52477",
    "CVE-2023-52482",
    "CVE-2023-52484",
    "CVE-2023-52486",
    "CVE-2023-52504",
    "CVE-2023-52516",
    "CVE-2023-52522",
    "CVE-2023-52528",
    "CVE-2023-52530",
    "CVE-2023-52568",
    "CVE-2023-52572",
    "CVE-2023-52575",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52606",
    "CVE-2023-52615",
    "CVE-2023-52616",
    "CVE-2024-1151",
    "CVE-2024-23851",
    "CVE-2024-24855",
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
    "CVE-2024-26606",
    "CVE-2024-26614",
    "CVE-2024-26625",
    "CVE-2024-26627"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-1873)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: crypto: lib/mpi - Fix unexpected
    pointer access in mpi_ec_init When the mpi_ec_ctx structure is initialized, some fields are not cleared,
    causing a crash when referencing the field when the structure was released. Initially, this issue was
    ignored because memory for mpi_ec_ctx is allocated with the __GFP_ZERO flag. For example, this error will
    be triggered when calculating the Za value for SM2 separately.(CVE-2023-52616)

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

    In the Linux kernel, the following vulnerability has been resolved: tcp: make sure init the accept_queue's
    spinlocks once When I run syz's reproduction C program locally, it causes the following issue:
    pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0! WARNING: CPU: 19 PID: 21160 at
    __pv_queued_spin_unlock_slowpath (kernel/locking/qspinlock_paravirt.h:508) Hardware name: Red Hat KVM,
    BIOS 0.5.1 01/01/2011 RIP: 0010:__pv_queued_spin_unlock_slowpath
    (kernel/locking/qspinlock_paravirt.h:508)(CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved: hwrng: core - Fix page fault dead lock
    on mmap-ed hwrng There is a dead-lock in the hwrng device read path. This triggers when the user reads
    from /dev/hwrng into memory also mmap-ed from /dev/hwrng. The resulting page fault triggers a recursive
    read which then dead-locks. Fix this by using a stack buffer when calling copy_to_user.(CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: fix potential key use-
    after-free When ieee80211_key_link() is called by ieee80211_gtk_rekey_add() but returns 0 due to KRACK
    protection (identical key reinstall), ieee80211_gtk_rekey_add() will still return a pointer into the key,
    in a potential use-after-free. This normally doesn't happen since it's only called by iwlwifi in case of
    WoWLAN rekey offload which has its own KRACK protection, but still better to fix, do that by returning an
    error code and converting that to success on the cfg80211 boundary only, leaving the error for bad callers
    of ieee80211_gtk_rekey_add().(CVE-2023-52530)

    In the Linux kernel, the following vulnerability has been resolved: powerpc/lib: Validate size for vector
    operations Some of the fp/vmx code in sstep.c assume a certain maximum size for the instructions being
    emulated. The size of those operations however is determined separately in analyse_instr(). Add a check to
    validate the assumption on the maximum size of the operations, so as to prevent any unintended kernel
    stack corruption.(CVE-2023-52606)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Return CQE error if invalid
    lkey was supplied RXE is missing update of WQE status in LOCAL_WRITE failures. This caused the following
    kernel panic if someone sent an atomic operation with an explicitly wrong lkey. (CVE-2021-47076)

    In the Linux kernel, the following vulnerability has been resolved:ceph: fix deadlock or deadcode of
    misusing dget().The lock order is incorrect between denty and its parent, we should always make sure that
    the parent get the lock first.But since this deadcode is never used and the parent dir will always be set
    from the callers, let's just remove it.(CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved:llc: call sock_orphan() at release
    time.syzbot reported an interesting trace [1] caused by a stale sk-sk_wq pointer in a closed llc
    socket.In commit ff7b11aa481f ('net: socket: set sock-sk to NULL after calling proto_ops::release()')
    Eric Biggers hinted that some protocols are missing a sock_orphan(), we need to perform a full audit.In
    net-next, I plan to clear sock-sk from sock_orphan() and amend Eric patch to add a
    warning.(CVE-2024-26625)

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

    In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev-stats fields. Handles updates to
    dev-stats.tx_dropped while we are at it.(CVE-2023-52578)

    In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking
    Releasing the `priv-lock` while iterating the `priv-multicast_list` in `ipoib_mcast_join_task()`
    opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the
    mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard
    lockup.(CVE-2023-52587)

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

    In the Linux kernel, the following vulnerability has been resolved: dma-debug: don't call
    __dma_entry_alloc_check_leak() under free_entries_lock __dma_entry_alloc_check_leak() calls into printk
    - serial console output (qcom geni) and grabs port-lock under free_entries_lock spin lock, which is
    a reverse locking dependency chain as qcom_geni IRQ handler can call into dma-debug code and grab
    free_entries_lock under port-lock. Move __dma_entry_alloc_check_leak() call out of free_entries_lock
    scope so that we don't acquire serial console's port-lock under it.(CVE-2023-52516)

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

    In the Linux kernel, the following vulnerability has been resolved:uio_hv_generic: Fix another memory leak
    in error handling paths Memory allocated by _x27;vmbus_alloc_ring()_x27; at the beginning of the probe
    function is never freed in the error handling path.Add the missing _x27;vmbus_free_ring()_x27; call.Note
    that it is already freed in the .remove function.(CVE-2021-47070)

    In the Linux kernel, the following vulnerability has been resolved:dmaengine: idxd: clear MSIX permission
    entry on shutdown.Add disabling/clearing of MSIX permission entries on device shutdown to mirror the
    enabling of the MSIX entries on probe. Current code left the MSIX enabled and the pasid entries still
    programmed at device shutdown.(CVE-2021-46918)

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
    do_el0_svc+0x34/0x60 el0_svc+0x2c/0xd4 el0t_64_sync_handler+0x114/0x140
    el0t_64_sync+0x1a4/0x1a8(CVE-2023-52484)

    In the Linux kernel, the following vulnerability has been resolved:ASoC: q6afe-clocks: fix reprobing of
    the driver.Q6afe-clocks driver can get reprobed. For example if the APR services.are restarted after the
    firmware crash. However currently Q6afe-clocks driver will oops because hw.init will get cleared during
    first _probe call. Rewrite the driver to fill the clock data at runtime rather than using big static array
    of clocks.(CVE-2021-47037)

    In the Linux kernel, the following vulnerability has been resolved: net: fix possible store tearing in
    neigh_periodic_work() While looking at a related syzbot report involving neigh_periodic_work(), I found
    that I forgot to add an annotation when deleting an RCU protected item from a list. Readers use
    rcu_deference(*np), we need to use either rcu_assign_pointer() or WRITE_ONCE() on writer side to prevent
    store tearing. I use rcu_assign_pointer() to have lockdep support, this was the choice made in
    neigh_flush_dev().(CVE-2023-52522)

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

    In the Linux kernel, the following vulnerability has been resolved:x86/srso: Fix SBPB enablement for
    spec_rstack_overflow=off.If the user has requested no SRSO mitigation, other mitigations can use the
    lighter-weight SBPB instead of IBPB.(CVE-2023-52575)

    In the Linux kernel, the following vulnerability has been resolved: x86/sgx: Resolves SECS reclaim vs.
    page fault for EAUG race The SGX EPC reclaimer (ksgxd) may reclaim the SECS EPC page for an enclave and
    set secs.epc_page to NULL. The SECS page is used for EAUG and ELDU in the SGX page fault handler. However,
    the NULL check for secs.epc_page is only done for ELDU, not EAUG before being used. Fix this by doing the
    same NULL check and reloading of the SECS page as needed for both EAUG and ELDU. The SECS page holds
    global enclave metadata. It can only be reclaimed when there are no other enclave pages remaining. At that
    point, virtually nothing can be done with the enclave until the SECS page is paged back in. An enclave can
    not run nor generate page faults without a resident SECS page. But it is still possible for a #PF for a
    non-SECS page to race with paging out the SECS page: when the last resident non-SECS page A triggers a #PF
    in a non-resident page B, and then page A and the SECS both are paged out before the #PF on B is handled.
    Hitting this bug requires that race triggered with a #PF for EAUG.(CVE-2023-52568)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: smsc75xx: Fix uninit-value
    access in __smsc75xx_read_reg syzbot reported the following uninit-value access issue:
    ===================================================== BUG: KMSAN: uninit-value in smsc75xx_wait_ready
    drivers/net/usb/smsc75xx.c:975 [inline] BUG: KMSAN: uninit-value in smsc75xx_bind+0x5c9/0x11e0
    drivers/net/usb/smsc75xx.c.(CVE-2023-52528)

    In the Linux kernel, the following vulnerability has been resolved: bpf: fix check for attempt to corrupt
    spilled pointer When register is spilled onto a stack as a 1/2/4-byte register, we set
    slot_type[BPF_REG_SIZE - 1] (plus potentially few more below it, depending on actual spill size). So to
    check if some stack slot has spilled register we need to consult slot_type[7], not slot_type[0]. To avoid
    the need to remember and double-check this in the future, just use is_spilled_reg()
    helper.(CVE-2023-52462)

    In the Linux kernel, the following vulnerability has been resolved: x86/fpu: Stop relying on userspace for
    info to fault in xsave buffer Before this change, the expected size of the user space buffer was taken
    from fx_sw-xstate_size. fx_sw-xstate_size can be changed from user-space, so it is possible
    construct a sigreturn frame where: * fx_sw-xstate_size is smaller than the size required by valid bits
    in fx_sw-xfeatures. * user-space unmaps parts of the sigrame fpu buffer so that not all of the buffer
    required by xrstor is accessible. In this case, xrstor tries to restore and accesses the unmapped area
    which results in a fault. But fault_in_readable succeeds because buf + fx_sw-xstate_size is within the
    still mapped area, so it goes back and tries xrstor again. It will spin in this loop forever. Instead,
    fault in the maximum size which can be touched by XRSTOR (taken from fpstate-user_size). [ dhansen:
    tweak subject / changelog ](CVE-2024-26603)

    In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix bugs with non-PAGE_SIZE-
    end multi-iovec user SDMA requests hfi1 user SDMA request processing has two bugs that can cause data
    corruption for user SDMA requests that have multiple payload iovecs where an iovec other than the tail
    iovec does not run up to the page boundary for the buffer pointed to by that iovec.a Here are the specific
    bugs: 1. user_sdma_txadd() does not use struct user_sdma_iovec-iov.iov_len. Rather, user_sdma_txadd()
    will add up to PAGE_SIZE bytes from iovec to the packet, even if some of those bytes are past iovec-
    iov.iov_len and are thus not intended to be in the packet. 2. user_sdma_txadd() and
    user_sdma_send_pkts() fail to advance to the next iovec in user_sdma_request-iovs when the current
    iovec is not PAGE_SIZE and does not contain enough data to complete the packet. The transmitted packet
    will contain the wrong data from the iovec pages. This has not been an issue with SDMA packets from hfi1
    Verbs or PSM2 because they only produce iovecs that end short of PAGE_SIZE as the tail iovec of an SDMA
    request. Fixing these bugs exposes other bugs with the SDMA pin cache (struct mmu_rb_handler) that get in
    way of supporting user SDMA requests with multiple payload iovecs whose buffers do not end at PAGE_SIZE.
    So this commit fixes those issues as well. Here are the mmu_rb_handler bugs that non-PAGE_SIZE-end multi-
    iovec payload user SDMA requests can hit: 1. Overlapping memory ranges in mmu_rb_handler will result in
    duplicate pinnings. 2. When extending an existing mmu_rb_handler entry (struct mmu_rb_node), the mmu_rb
    code (1) removes the existing entry under a lock, (2) releases that lock, pins the new pages, (3) then
    reacquires the lock to insert the extended mmu_rb_node. If someone else comes in and inserts an
    overlapping entry between (2) and (3), insert in (3) will fail. The failure path code in this case unpins
    _all_ pages in either the original mmu_rb_node or the new mmu_rb_node that was inserted between (2) and
    (3). 3. In hfi1_mmu_rb_remove_unless_exact(), mmu_rb_node-refcount is incremented outside of
    mmu_rb_handler-lock. As a result, mmu_rb_node could be evicted by another thread that gets
    mmu_rb_handler-lock and checks mmu_rb_node-refcount before mmu_rb_node-refcount is incremented.
    4. Related to #2 above, SDMA request submission failure path does not check mmu_rb_node-refcount before
    freeing mmu_rb_node object. If there are other SDMA requests in progress whose iovecs have pointers to the
    now-freed mmu_rb_node(s), those pointers to the now-freed mmu_rb nodes will be dereferenced when those
    SDMA requests complete.(CVE-2023-52474)

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

    In the Linux kernel, the following vulnerability has been resolved: x86/srso: Add SRSO mitigation for
    Hygon processors Add mitigation for the speculative return stack overflow vulnerability which exists on
    Hygon processors too.(CVE-2023-52482)

    In the Linux kernel, the following vulnerability has been resolved: usb: hub: Guard against accesses to
    uninitialized BOS descriptors Many functions in drivers/usb/core/hub.c and drivers/usb/core/hub.h access
    fields inside udev-bos without checking if it was allocated and initialized. If
    usb_get_bos_descriptor() fails for whatever reason, udev-bos will be NULL and those accesses will
    result in a crash: BUG: kernel NULL pointer dereference(CVE-2023-52477)

    In the Linux kernel, the following vulnerability has been resolved: sched/membarrier: reduce the ability
    to hammer on sys_membarrier On some systems, sys_membarrier can be very expensive, causing overall
    slowdowns for everything. So put a lock on the path in order to serialize the accesses to prevent the
    ability for this to be called at too high of a frequency and saturate the machine.(CVE-2024-26602)

    In the Linux kernel, the following vulnerability has been resolved: binder: signal epoll threads of self-
    work In (e)poll mode, threads often depend on I/O events to determine when data is ready for consumption.
    Within binder, a thread may initiate a command via BINDER_WRITE_READ without a read buffer and then make
    use of epoll_wait() or similar to consume any responses afterwards. It is then crucial that epoll threads
    are signaled via wakeup when they queue their own work. Otherwise, they risk waiting indefinitely for an
    event leaving their work unhandled. What is worse, subsequent commands won't trigger a wakeup either as
    the thread has pending work.(CVE-2024-26606)

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

    In the Linux kernel, the following vulnerability has been resolved: apparmor: avoid crash when parsed
    profile name is empty When processing a packed profile in unpack_profile() described like 'profile
    :ns::samba-dcerpcd /usr/lib*/samba/{,samba/}samba-dcerpcd {...}' a string ':samba-dcerpcd' is unpacked as
    a fully-qualified name and then passed to aa_splitn_fqname(). aa_splitn_fqname() treats ':samba-dcerpcd'
    as only containing a namespace. Thus it returns NULL for tmpname, meanwhile tmpns is non-NULL. Later
    aa_alloc_profile() crashes as the new profile name is NULL now.(CVE-2023-52443)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    A race condition was found in the Linux kernel's scsi device driver in lpfc_unregister_fcf_rescan()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24855)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Reject variable offset alu on
    PTR_TO_FLOW_KEYS For PTR_TO_FLOW_KEYS, check_flow_keys_access() only uses fixed off for validation.
    However, variable offset ptr alu is not prohibited for this ptr kind. So the variable offset is not
    checked.(CVE-2024-26589)

    In tIn the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-its: Avoid
    potential UAF in LPI translation cache There is a potential UAF scenario in the case of an LPI translation
    cache hit racing with an operation that invalidates the cache, such as a DISCARD ITS command. The root of
    the problem is that vgic_its_check_cache() does not elevate the refcount on the vgic_irq before dropping
    the lock that serializes refcount changes. Have vgic_its_check_cache() raise the refcount on the returned
    vgic_irq and add the corresponding decrement after queueing the interrupt.(CVE-2024-26598)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_rbtree: skip sync
    GC for new elements in this transaction New elements in this transaction might expired before such
    transaction ends. Skip sync GC for such elements otherwise commit path might walk over an already released
    object. Once transaction is finished, async GC will collect such expired element.(CVE-2023-52433)

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

    In the Linux kernel, the following vulnerability has been resolved: drivers/amd/pm: fix a use-after-free
    in kv_parse_power_table When ps allocated by kzalloc equals to NULL, kv_parse_power_table frees adev-
    pm.dpm.ps that allocated before. However, after the control flow goes through the following call
    chains: kv_parse_power_table |- kv_dpm_init |- kv_dpm_sw_init |- kv_dpm_fini The adev-
    pm.dpm.ps is used in the for loop of kv_dpm_fini after its first free in kv_parse_power_table and
    causes a use-after-free bug.(CVE-2023-52469)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix stack
    corruption When tc filters are first added to a net device, the corresponding local port gets bound to an
    ACL group in the device. The group contains a list of ACLs. In turn, each ACL points to a different TCAM
    region where the filters are stored. During forwarding, the ACLs are sequentially evaluated until a match
    is found. One reason to place filters in different regions is when they are added with decreasing
    priorities and in an alternating order so that two consecutive filters can never fit in the same region
    because of their key usage. In Spectrum-2 and newer ASICs the firmware started to report that the maximum
    number of ACLs in a group is more than 16, but the layout of the register that configures ACL groups
    (PAGT) was not updated to account for that. It is therefore possible to hit stack corruption [1] in the
    rare case where more than 16 ACLs in a group are required. Fix by limiting the maximum ACL group size to
    the minimum between what the firmware reports and the maximum ACLs that fit in the PAGT register. Add a
    test case to make sure the machine does not crash when this condition is hit. (CVE-2024-26586)

    In the Linux kernel, the following vulnerability has been resolved: ext4: regenerate buddy after block
    freeing failed if under fc replay This mostly reverts commit 6bd97bf273bd ('ext4: remove redundant
    mb_regenerate_buddy()') and reintroduces mb_regenerate_buddy(). Based on code in mb_free_blocks(), fast
    commit replay can end up marking as free blocks that are already marked as such. This causes corruption of
    the buddy bitmap so we need to regenerate it in that case.(CVE-2024-26601)

    In the Linux kernel, the following vulnerability has been resolved: net: qualcomm: rmnet: fix global oob
    in rmnet_policy The variable rmnet_link_ops assign a *bigger* maxtype which leads to a global out-of-
    bounds read when parsing the netlink attributes.(CVE-2024-26597)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on
    context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func
    function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that
    might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check
    before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: net: tls: handle backlogging of crypto
    requests Since we're setting the CRYPTO_TFM_REQ_MAY_BACKLOG flag on our requests to the crypto API,
    crypto_aead_{encrypt,decrypt} can return -EBUSY instead of -EINPROGRESS in valid situations. For example,
    when the cryptd queue for AESNI is full (easy to trigger with an artificially low
    cryptd.cryptd_max_cpu_qlen), requests will be enqueued to the backlog but still processed. In that case,
    the async callback will also be called twice: first with err == -EINPROGRESS, which it seems we can just
    ignore, then with err == 0. Compared to Sabrina's original patch this version uses the new
    tls_*crypt_async_wait() helpers and converts the EBUSY to EINPROGRESS to avoid having to modify all the
    error handling paths. The handling is identical.(CVE-2024-26584)

    In the Linux kernel, the following vulnerability has been resolved: tls: fix race between async notify and
    socket close The submitting thread (one which called recvmsg/sendmsg) may exit as soon as the async crypto
    handler calls complete() so any code past that point risks touching already freed data. Try to avoid the
    locking and extra flags altogether. Have the main thread hold an extra reference, this way we can depend
    solely on the atomic ref counter for synchronization. Don't futz with reiniting the completion, either, we
    are now tightly controlling when completion fires.(CVE-2024-26583)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_rbtree: skip end
    interval element from gc rbtree lazy gc on insert might collect an end interval element that has been just
    added in this transactions, skip end interval elements that are not yet active.(CVE-2024-26581)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-tcp: Fix a kernel panic when
    host sends an invalid H2C PDU length If the host sends an H2CData command with an invalid DATAL, the
    kernel may crash in nvmet_tcp_build_pdu_iovec(). (CVE-2023-52454)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix NULL
    pointer dereference in error path When calling mlxsw_sp_acl_tcam_region_destroy() from an error path after
    failing to attach the region to an ACL group, we hit a NULL pointer dereference upon 'region-group-
    tcam' .(CVE-2024-26595)

    In the Linux kernel, the following vulnerability has been resolved: gfs2: Fix kernel NULL pointer
    dereference in gfs2_rgrp_dump Syzkaller has reported a NULL pointer dereference when accessing rgd-
    rd_rgl in gfs2_rgrp_dump(). This can happen when creating rgd-rd_gl fails in read_rindex_entry().
    Add a NULL pointer check in gfs2_rgrp_dump() to prevent that.(CVE-2023-52448)

    In the Linux kernel, the following vulnerability has been resolved: efivarfs: force RO when remounting if
    SetVariable is not supported If SetVariable at runtime is not supported by the firmware we never assign a
    callback for that function. At the same time mount the efivarfs as RO so no one can call that. However, we
    never check the permission flags when someone remounts the filesystem as RW.(CVE-2023-52463)

    In the Linux kernel, the following vulnerability has been resolved: i2c: i801: Fix block process call
    transactions According to the Intel datasheets, software must reset the block buffer index twice for block
    process call transactions: once before writing the outgoing data to the buffer, and once again before
    reading the incoming data from the buffer. The driver is currently missing the second reset, causing the
    wrong portion of the block buffer to be read.(CVE-2024-26593)

    In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-its: Avoid potential
    UAF in LPI translation cache There is a potential UAF scenario in the case of an LPI translation cache hit
    racing with an operation that invalidates the cache, such as a DISCARD ITS command. The root of the
    problem is that vgic_its_check_cache() does not elevate the refcount on the vgic_irq before dropping the
    lock that serializes refcount changes. Have vgic_its_check_cache() raise the refcount on the returned
    vgic_irq and add the corresponding decrement after queueing the interrupt.(CVE-2024-26598)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_rbtree: skip sync
    GC for new elements in this transaction New elements in this transaction might expired before such
    transaction ends. Skip sync GC for such elements otherwise commit path might walk over an already released
    object. Once transaction is finished, async GC will collect such expired element.(CVE-2023-52433)

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

    In the Linux kernel, the following vulnerability has been resolved: drivers/amd/pm: fix a use-after-free
    in kv_parse_power_table When ps allocated by kzalloc equals to NULL, kv_parse_power_table frees adev-
    pm.dpm.ps that allocated before. However, after the control flow goes through the following call
    chains: kv_parse_power_table |- kv_dpm_init |- kv_dpm_sw_init |- kv_dpm_fini The adev-
    pm.dpm.ps is used in the for loop of kv_dpm_fini after its first free in kv_parse_power_table and
    causes a use-after-free bug.(CVE-2023-52469)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix stack
    corruption When tc filters are first added to a net device, the corresponding local port gets bound to an
    ACL group in the device. The group contains a list of ACLs. In turn, each ACL points to a different TCAM
    region where the filters are stored. During forwarding, the ACLs are sequentially evaluated until a match
    is found. One reason to place filters in different regions is when they are added with decreasing
    priorities and in an alternating order so that two consecutive filters can never fit in the same region
    because of their key usage. In Spectrum-2 and newer ASICs the firmware started to report that the maximum
    number of ACLs in a group is more than 16, but the layout of the register that configures ACL groups
    (PAGT) was not updated to account for that. It is therefore possible to hit stack corruption [1] in the
    rare case where more than 16 ACLs in a group are required. Fix by limiting the maximum ACL group size to
    the minimum between what the firmware reports and the maximum ACLs that fit in the PAGT register. Add a
    test case to make sure the machine does not crash when this condition is hit. (CVE-2024-26586)

    In the Linux kernel, the following vulnerability has been resolved: ext4: regenerate buddy after block
    freeing failed if under fc replay This mostly reverts commit 6bd97bf273bd ('ext4: remove redundant
    mb_regenerate_buddy()') and reintroduces mb_regenerate_buddy(). Based on code in mb_free_blocks(), fast
    commit replay can end up marking as free blocks that are already marked as such. This causes corruption of
    the buddy bitmap so we need to regenerate it in that case.(CVE-2024-26601)

    In the Linux kernel, the following vulnerability has been resolved: net: qualcomm: rmnet: fix global oob
    in rmnet_policy The variable rmnet_link_ops assign a *bigger* maxtype which leads to a global out-of-
    bounds read when parsing the netlink attributes. (CVE-2024-26597)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on
    context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func
    function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that
    might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check
    before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: net: tls: handle backlogging of crypto
    requests Since we're setting the CRYPTO_TFM_REQ_MAY_BACKLOG flag on our requests to the crypto API,
    crypto_aead_{encrypt,decrypt} can return -EBUSY instead of -EINPROGRESS in valid situations. For example,
    when the cryptd queue for AESNI is full (easy to trigger with an artificially low
    cryptd.cryptd_max_cpu_qlen), requests will be enqueued to the backlog but still processed. In that case,
    the async callback will also be called twice: first with err == -EINPROGRESS, which it seems we can just
    ignore, then with err == 0. Compared to Sabrina's original patch this version uses the new
    tls_*crypt_async_wait() helpers and converts the EBUSY to EINPROGRESS to avoid having to modify all the
    error handling paths. The handling is identical.(CVE-2024-26584)

    In the Linux kernel, the following vulnerability has been resolved: tls: fix race between async notify and
    socket close The submitting thread (one which called recvmsg/sendmsg) may exit as soon as the async crypto
    handler calls complete() so any code past that point risks touching already freed data. Try to avoid the
    locking and extra flags altogether. Have the main thread hold an extra reference, this way we can depend
    solely on the atomic ref counter for synchronization. Don't futz with reiniting the completion, either, we
    are now tightly controlling when completion fires.(CVE-2024-26583)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_rbtree: skip end
    interval element from gc rbtree lazy gc on insert might collect an end interval element that has been just
    added in this transactions, skip end interval elements that are not yet active.(CVE-2024-26581)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-tcp: Fix a kernel panic when
    host sends an invalid H2C PDU length If the host sends an H2CData command with an invalid DATAL, the
    kernel may crash in nvmet_tcp_build_pdu_iovec(). (CVE-2023-52454)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix NULL
    pointer dereference in error path When calling mlxsw_sp_acl_tcam_region_destroy() from an error path after
    failing to attach the region to an ACL group, we hit a NULL pointer dereference upon 'region-group-
    tcam' .(CVE-2024-26595)

    In the Linux kernel, the following vulnerability has been resolved: gfs2: Fix kernel NULL pointer
    dereference in gfs2_rgrp_dump Syzkaller has reported a NULL pointer dereference when accessing rgd-
    rd_rgl in gfs2_rgrp_dump(). This can happen when creating rgd-rd_gl fails in read_rindex_entry().
    Add a NULL pointer check in gfs2_rgrp_dump() to prevent that.(CVE-2023-52448)

    In the Linux kernel, the following vulnerability has been resolved: efivarfs: force RO when remounting if
    SetVariable is not supported If SetVariable at runtime is not supported by the firmware we never assign a
    callback for that function. At the same time mount the efivarfs as RO so no one can call that. However, we
    never check the permission flags when someone remounts the filesystem as RW. (CVE-2023-52463)

    In the Linux kernel, the following vulnerability has been resolved: i2c: i801: Fix block process call
    transactions According to the Intel datasheets, software must reset the block buffer index twice for block
    process call transactions: once before writing the outgoing data to the buffer, and once again before
    reading the incoming data from the buffer. The driver is currently missing the second reset, causing the
    wrong portion of the block buffer to be read.(CVE-2024-26593)

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

    A flaw was found in the smb client in the Linux kernel. A potential out-of-bounds error was seen in the
    smb2_parse_contexts() function. Validate offsets and lengths before dereferencing create contexts in
    smb2_parse_contexts().(CVE-2023-52434)

    A flaw was found in the Linux kernels net/core/skbuff.c subsystem. The GSO_BY_FRAGS is a forbidden
    value and allows the following computation in skb_segment() to reach it. The : mss = mss * partial_segs
    and many initial mss values can lead to a bad final result. Limit the segmentation so that the new mss
    value is smaller than GSO_BY_FRAGS.(CVE-2023-52435)

    In the Linux kernel, the following vulnerability has been resolved:tls: fix race between tx work
    scheduling and socket close.Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit
    as soon as the async crypto handler calls complete().Reorder scheduling the work before calling
    complete().This seems more logical in the first place, as it's the inverse order of what the submitting
    thread will do.(CVE-2024-26585)

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

    copy_params in drivers/md/dm-ioctl.c in the Linux kernel through 6.7.1 can attempt to allocate more than
    INT_MAX bytes, and crash, because of a missing param_kernel-data_size check. This is related to
    ctl_ioctl.(CVE-2024-23851)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1873
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c9835b9");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/28");

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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-136.12.0.86.h1903.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h1903.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h1903.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h1903.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h1903.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h1903.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
