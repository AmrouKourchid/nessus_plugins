#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205957);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id(
    "CVE-2021-47265",
    "CVE-2021-47427",
    "CVE-2021-47469",
    "CVE-2022-48651",
    "CVE-2022-48666",
    "CVE-2022-48689",
    "CVE-2022-48692",
    "CVE-2022-48703",
    "CVE-2023-52652",
    "CVE-2023-52656",
    "CVE-2023-52672",
    "CVE-2023-52676",
    "CVE-2023-52677",
    "CVE-2023-52683",
    "CVE-2023-52693",
    "CVE-2023-52698",
    "CVE-2023-52732",
    "CVE-2023-52752",
    "CVE-2023-52753",
    "CVE-2023-52757",
    "CVE-2023-52759",
    "CVE-2023-52762",
    "CVE-2023-52764",
    "CVE-2023-52796",
    "CVE-2023-52808",
    "CVE-2023-52814",
    "CVE-2023-52818",
    "CVE-2023-52831",
    "CVE-2023-52832",
    "CVE-2023-52835",
    "CVE-2023-52843",
    "CVE-2023-52847",
    "CVE-2023-52859",
    "CVE-2023-52864",
    "CVE-2023-52868",
    "CVE-2023-52869",
    "CVE-2024-26830",
    "CVE-2024-26845",
    "CVE-2024-26857",
    "CVE-2024-26915",
    "CVE-2024-26923",
    "CVE-2024-26924",
    "CVE-2024-26925",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26947",
    "CVE-2024-26953",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26973",
    "CVE-2024-26974",
    "CVE-2024-26976",
    "CVE-2024-26982",
    "CVE-2024-26984",
    "CVE-2024-26988",
    "CVE-2024-26993",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27012",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27017",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27038",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27046",
    "CVE-2024-27059",
    "CVE-2024-27065",
    "CVE-2024-27073",
    "CVE-2024-27075",
    "CVE-2024-27389",
    "CVE-2024-27395",
    "CVE-2024-27397",
    "CVE-2024-27403",
    "CVE-2024-27415",
    "CVE-2024-27431",
    "CVE-2024-35790",
    "CVE-2024-35791",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35823",
    "CVE-2024-35835",
    "CVE-2024-35847",
    "CVE-2024-35852",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35870",
    "CVE-2024-35877",
    "CVE-2024-35879",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35900",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35910",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35939",
    "CVE-2024-35950",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35967",
    "CVE-2024-35973",
    "CVE-2024-35984",
    "CVE-2024-35989",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-36000",
    "CVE-2024-36004",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36008",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36031",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36898",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36908",
    "CVE-2024-36914",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36924",
    "CVE-2024-36927",
    "CVE-2024-36933",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36959",
    "CVE-2024-36968",
    "CVE-2024-36971",
    "CVE-2024-36978",
    "CVE-2024-38564",
    "CVE-2024-38601",
    "CVE-2024-38662"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2024-2206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: af_unix: Fix garbage collector racing
    against connect() Garbage collector does not take into account the risk of embryo getting enqueued during
    the garbage collection. If such embryo has a peer that carries SCM_RIGHTS, two consecutive passes of
    scan_children() may see a different set of children. Leading to an incorrectly elevated inflight count,
    and then a dangling pointer within the gc_inflight_list. sockets are AF_UNIX/SOCK_STREAM S is an
    unconnected socket L is a listening in-flight socket bound to addr, not in fdtable V's fd will be passed
    via sendmsg(), gets inflight count bumped connect(S, addr) sendmsg(S, [V]); close(V) __unix_gc()
    ---------------- ------------------------- ----------- NS = unix_create1() skb1 = sock_wmalloc(NS) L =
    unix_find_other(addr) unix_state_lock(L) unix_peer(S) = NS // V count=1 inflight=0 NS = unix_peer(S) skb2
    = sock_alloc() skb_queue_tail(NS, skb2[V]) // V became in-flight // V count=2 inflight=1 close(V) // V
    count=1 inflight=1 // GC candidate condition met for u in gc_inflight_list: if (total_refs ==
    inflight_refs) add u to gc_candidates // gc_candidates={L, V} for u in gc_candidates: scan_children(u,
    dec_inflight) // embryo (skb1) was not // reachable from L yet, so V's // inflight remains unchanged
    __skb_queue_tail(L, skb1) unix_state_unlock(L) for u in gc_candidates: if (u.inflight) scan_children(u,
    inc_inflight_move_tail) // V count=1 inflight=2 (!) If there is a GC-candidate listening socket,
    lock/unlock its state. This makes GC wait until the end of any ongoing connect() to that socket. After
    flipping the lock, a possibly SCM-laden embryo is already enqueued. And if there is another embryo coming,
    it can not possibly carry SCM_RIGHTS. At this point, unix_inflight() can not happen because unix_gc_lock
    is already taken. Inflight graph remains unaffected.(CVE-2024-26923)

    In the Linux kernel, the following vulnerability has been resolved: crypto: qat - resolve race condition
    during AER recovery During the PCI AER system's error recovery process, the kernel driver may encounter a
    race condition with freeing the reset_data structure's memory. If the device restart will take more than
    10 seconds the function scheduling that restart will exit due to a timeout, and the reset_data structure
    will be freed. However, this data structure is used for completion notification after the restart is
    completed, which leads to a UAF bug.(CVE-2024-26974)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Reset IH OVERFLOW_CLEAR
    bit Allows us to detect subsequent IH ring buffer overflows as well.(CVE-2024-26915)

    In the Linux kernel, the following vulnerability has been resolved: drm: nv04: Fix out of bounds access
    When Output Resource (dcb-or) value is assigned in fabricate_dcb_output(), there may be out of bounds
    access to dac_users array in case dcb-or is zero because ffs(dcb-or) is used as index there. The
    'or' argument of fabricate_dcb_output() must be interpreted as a number of bit to set, not value. Utilize
    macros from 'enum nouveau_or' in calls instead of hardcoding. Found by Linux Verification Center
    (linuxtesting.org) with SVACE.(CVE-2024-27008)

    In the Linux kernel, the following vulnerability has been resolved: fat: fix uninitialized field in
    nostale filehandles When fat_encode_fh_nostale() encodes file handle without a parent it stores only first
    10 bytes of the file handle. However the length of the file handle must be a multiple of 4 so the file
    handle is actually 12 bytes long and the last two bytes remain uninitialized. This is not great at we
    potentially leak uninitialized information with the handle to userspace. Properly initialize the full
    handle length.(CVE-2024-26973)

    In the Linux kernel, the following vulnerability has been resolved: fs: sysfs: Fix reference leak in
    sysfs_break_active_protection() The sysfs_break_active_protection() routine has an obvious reference leak
    in its error path. If the call to kernfs_find_and_get() fails then kn will be NULL, so the companion
    sysfs_unbreak_active_protection() routine won't get called (and would only cause an access violation by
    trying to dereference kn-parent if it was called). As a result, the reference to kobj acquired at the
    start of the function will never be released. Fix the leak by adding an explicit kobject_put() call when
    kn is NULL.(CVE-2024-26993)

    In the Linux kernel, the following vulnerability has been resolved: geneve: make sure to pull inner header
    in geneve_rx() syzbot triggered a bug in geneve_rx() [1] Issue is similar to the one I fixed in commit
    8d975c15c0cd ('ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()') We have to save skb-
    network_header in a temporary variable in order to be able to recompute the network_header pointer
    after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure the needed headers are in skb-
    head.(CVE-2024-26857)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Always flush async #PF workqueue
    when vCPU is being destroyed Always flush the per-vCPU async #PF workqueue when a vCPU is clearing its
    completion queue, e.g. when a VM and all its vCPUs is being destroyed. KVM must ensure that none of its
    workqueue callbacks is running when the last reference to the KVM _module_ is put. Gifting a reference to
    the associated VM prevents the workqueue callback from dereferencing freed vCPU/VM memory, but does not
    prevent the KVM module from being unloaded before the callback completes. Drop the misguided VM refcount
    gifting, as calling kvm_put_kvm() from async_pf_execute() if kvm_put_kvm() flushes the async #PF workqueue
    will result in deadlock. async_pf_execute() can't return until kvm_put_kvm() finishes, and kvm_put_kvm()
    can't return until async_pf_execute() finishes: WARNING: CPU: 8 PID: 251 at virt/kvm/kvm_main.c:1435
    kvm_put_kvm+0x2d/0x320 [kvm] Modules linked in: vhost_net vhost vhost_iotlb tap kvm_intel kvm irqbypass
    CPU: 8 PID: 251 Comm: kworker/8:1 Tainted: G W 6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119 Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015 Workqueue: events async_pf_execute [kvm] RIP:
    0010:kvm_put_kvm+0x2d/0x320 [kvm](CVE-2024-26976)

    In the Linux kernel, the following vulnerability has been resolved: mac802154: fix llsec key resources
    release in mac802154_llsec_key_del mac802154_llsec_key_del() can free resources of a key directly without
    following the RCU rules for waiting before the end of a grace period. This may lead to use-after-free in
    case llsec_lookup_key() is traversing the list of keys in parallel with a key deletion: refcount_t:
    addition on 0; use-after-free.(CVE-2024-26961)

    In the Linux kernel, the following vulnerability has been resolved: media: edia: dvbdev: fix a use-after-
    free In dvb_register_device, *pdvbdev is set equal to dvbdev, which is freed in several error-handling
    paths. However, *pdvbdev is not set to NULL after dvbdev's deallocation, causing use-after-frees in many
    places, for example, in the following call chain: budget_register |- dvb_dmxdev_init |-
    dvb_register_device |- dvb_dmxdev_release |- dvb_unregister_device |- dvb_remove_device |-
    dvb_device_put |- kref_put When calling dvb_unregister_device, dmxdev-dvbdev (i.e. *pdvbdev in
    dvb_register_device) could point to memory that had been freed in dvb_register_device. Thereafter, this
    pointer is transferred to kref_put and triggering a use-after-free.(CVE-2024-27043)

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27075)

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27073)

    In the Linux kernel, the following vulnerability has been resolved: mm: swap: fix race between
    free_swap_and_cache() and swapoff() There was previously a theoretical window where swapoff() could run
    and teardown a swap_info_struct while a call to free_swap_and_cache() was running in another thread. This
    could cause, amongst other bad possibilities, swap_page_trans_huge_swapped() (called by
    free_swap_and_cache()) to access the freed memory for swap_map. This is a theoretical problem and I
    haven't been able to provoke it from a test case. But there has been agreement based on code review that
    this is possible (see link below). Fix it by using get_swap_device()/put_swap_device(), which will stall
    swapoff(). There was an extra check in _swap_info_get() to confirm that the swap entry was not free. This
    isn't present in get_swap_device() because it doesn't make sense in general due to the race between
    getting the reference and swapoff. So I've added an equivalent check directly in
    free_swap_and_cache().(CVE-2024-26960)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Prevent deadlock while
    disabling aRFS When disabling aRFS under the `priv-state_lock`, any scheduled aRFS works are canceled
    using the `cancel_work_sync` function, which waits for the work to end if it has already started. However,
    while waiting for the work handler, the handler will try to acquire the `state_lock` which is already
    acquired. The worker acquires the lock to delete the rules if the state is down, which is not the worker's
    responsibility since disabling aRFS deletes the rules. Add an aRFS state variable, which indicates whether
    the aRFS is enabled and prevent adding rules when the aRFS is disabled.(CVE-2024-27014)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: Fix mirred deadlock on
    device recursion When the mirred action is used on a classful egress qdisc and a packet is mirrored or
    redirected to self we hit a qdisc lock deadlock.(CVE-2024-27010)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix memleak in
    map from abort path The delete set command does not rely on the transaction object for element removal,
    therefore, a combination of delete element + delete set from the abort path could result in restoring
    twice the refcount of the mapping. Check for inactive element in the next generation for the delete
    element command in the abort path, skip restoring state if next generation bit has been already cleared.
    This is similar to the activate logic using the set walk iterator.(CVE-2024-27011)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: Fix potential
    data-race in __nft_expr_type_get() nft_unregister_expr() can concurrent with __nft_expr_type_get(), and
    there is not any protection when iterate over nf_tables_expressions list in __nft_expr_type_get().
    Therefore, there is potential data-race of nf_tables_expressions list entry. Use list_for_each_entry_rcu()
    to iterate over nf_tables_expressions list in __nft_expr_type_get(), and use rcu_read_lock() in the caller
    nft_expr_type_get() to protect the entire type query process.(CVE-2024-27020)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: Fix potential
    data-race in __nft_obj_type_get() nft_unregister_obj() can concurrent with __nft_obj_type_get(), and there
    is not any protection when iterate over nf_tables_objects list in __nft_obj_type_get(). Therefore, there
    is potential data-race of nf_tables_objects list entry. Use list_for_each_entry_rcu() to iterate over
    nf_tables_objects list in __nft_obj_type_get(), and use rcu_read_lock() in the caller nft_obj_type_get()
    to protect the entire type query process.(CVE-2024-27019)

    In the Linux kernel, the following vulnerability has been resolved: nfp: flower: handle acti_netdevs
    allocation failure The kmalloc_array() in nfp_fl_lag_do_work() will return null, if the physical memory
    has run out. As a result, if we dereference the acti_netdevs, the null pointer dereference bugs will
    happen. This patch adds a check to judge whether allocation failure occurs. If it happens, the delayed
    work will be rescheduled and try again.(CVE-2024-27046)

    In the Linux kernel, the following vulnerability has been resolved: nfs: fix UAF in direct writes In
    production we have been hitting the following warning consistently(CVE-2024-26958)

    In the Linux kernel, the following vulnerability has been resolved: NTB: fix possible name leak in
    ntb_register_device() If device_register() fails in ntb_register_device(), the device name allocated by
    dev_set_name() should be freed. As per the comment in device_register(), callers should use put_device()
    to give up the reference in the error path. So fix this by calling put_device() in the error path so that
    the name can be freed in kobject_cleanup(). As a result of this, put_device() in the error path of
    ntb_register_device() is removed and the actual error is returned.(CVE-2023-52652)

    In the Linux kernel, the following vulnerability has been resolved: perf/core: Bail out early if the
    request AUX area is out of bound When perf-record with a large AUX area, e.g 4GB, it fails with: #perf
    record -C 0 -m ,4G -e arm_spe_0// -- sleep 1 failed to mmap with 12 (Cannot allocate memory) and it
    reveals a WARNING with __alloc_pages()(CVE-2023-52835)

    In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix command flush on
    cable pull System crash due to command failed to flush back to SCSI layer. BUG: unable to handle kernel
    NULL pointer dereference at 0000000000000000 PGD 0 P4D 0 Oops: 0000(CVE-2024-26931)

    In the Linux kernel, the following vulnerability has been resolved: scsi: target: core: Add TMF to
    tmr_list handling An abort that is responded to by iSCSI itself is added to tmr_list but does not go to
    target core. A LUN_RESET that goes through tmr_list takes a refcounter on the abort and waits for
    completion. However, the abort will be never complete because it was not started in target
    core.(CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved: Squashfs: check the inode number is
    not the invalid value of zero Syskiller has produced an out of bounds access in fill_meta_index(). That
    out of bounds access is ultimately caused because the inode has an inode number with the invalid value of
    zero, which was not checked. The reason this causes the out of bounds access is due to following sequence
    of events: 1. Fill_meta_index() is called to allocate (via empty_meta_index()) and fill a metadata index.
    It however suffers a data read error and aborts, invalidating the newly returned empty metadata index. It
    does this by setting the inode number of the index to zero, which means unused (zero is not a valid inode
    number). 2. When fill_meta_index() is subsequently called again on another read operation,
    locate_meta_index() returns the previous index because it matches the inode number of 0. Because this
    index has been returned it is expected to have been filled, and because it hasn't been, an out of bounds
    access is performed. This patch adds a sanity check which checks that the inode number is not zero when
    the inode is created and returns -EINVAL if it is.(CVE-2024-26982)

    In the Linux kernel, the following vulnerability has been resolved: tun: limit printing rate when illegal
    packet received by tun dev vhost_worker will call tun call backs to receive packets. If too many illegal
    packets arrives, tun_do_read will keep dumping packet contents. When console is enabled, it will costs
    much more cpu time to dump packet and soft lockup will be detected. net_ratelimit mechanism can be used to
    limit the dumping rate.(CVE-2024-27013)

    In the Linux kernel, the following vulnerability has been resolved: USB: core: Fix deadlock in
    usb_deauthorize_interface() Among the attribute file callback routines in drivers/usb/core/sysfs.c, the
    interface_authorized_store() function is the only one which acquires a device lock on an ancestor device:
    It calls usb_deauthorize_interface(), which locks the interface's parent USB device. The will lead to
    deadlock if another process already owns that lock and tries to remove the interface, whether through a
    configuration change or because the device has been disconnected. As part of the removal procedure,
    device_del() waits for all ongoing sysfs attribute callbacks to complete. But usb_deauthorize_interface()
    can't complete until the device lock has been released, and the lock won't be released until the removal
    has finished. The mechanism provided by sysfs to prevent this kind of deadlock is to use the
    sysfs_break_active_protection() function, which tells sysfs not to wait for the attribute
    callback.(CVE-2024-26934)

    In the Linux kernel, the following vulnerability has been resolved: USB: usb-storage: Prevent divide-by-0
    error in isd200_ata_command The isd200 sub-driver in usb-storage uses the HEADS and SECTORS values in the
    ATA ID information to calculate cylinder and head values when creating a CDB for READ or WRITE commands.
    The calculation involves division and modulus operations, which will cause a crash if either of these
    values is 0. While this never happens with a genuine device, it could happen with a flawed or subversive
    emulation, as reported by the syzbot fuzzer. Protect against this possibility by refusing to bind to the
    device if either the ATA_ID_HEADS or ATA_ID_SECTORS value in the device's ID information is 0. This
    requires isd200_Initialization() to return a negative error code when initialization fails; currently it
    always returns 0 (even when there is an error).(CVE-2024-27059)

    In the Linux kernel, the following vulnerability has been resolved:drm/client: Fully protect modes[] with
    dev-mode_config.mutex.The modes[] array contains pointers to modes on the connectors' mode lists, which
    are protected by dev-mode_config.mutex.Thus we need to extend modes[] the same protection or by the
    time we use it the elements may already be pointing to freed/reused memory.(CVE-2024-35950)

    In the Linux kernel, the following vulnerability has been resolved:net: openvswitch: Fix Use-After-Free in
    ovs_ct_exit.Since kfree_rcu, which is called in the hlist_for_each_entry_rcu traversal of
    ovs_ct_limit_exit, is not part of the RCU read critical section, it is possible that the RCU grace period
    will pass during the traversal and the key will be free.To prevent this, it should be changed to
    hlist_for_each_entry_safe.(CVE-2024-27395)

    In the Linux kernel, the following vulnerability has been resolved: pstore: inode: Only d_invalidate() is
    needed Unloading a modular pstore backend with records in pstorefs would trigger the dput() double-drop
    warning: WARNING: CPU: 0 PID: 2569 at fs/dcache.c:762 dput.part.0+0x3f3/0x410 Using the combo of
    d_drop()/dput() (as mentioned in Documentation/filesystems/vfs.rst) isn't the right approach here, and
    leads to the reference counting problem seen above. Use d_invalidate() and update the code to not bother
    checking for error codes that can never happen.(CVE-2024-27389)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Fix potential NULL
    pointer dereferences in 'dcn10_set_output_transfer_func()' The 'stream' pointer is used in
    dcn10_set_output_transfer_func() before the check if 'stream' is NULL. Fixes the below:
    drivers/gpu/drm/amd/amdgpu/../display/dc/hwss/dcn10/dcn10_hwseq.c:1892 dcn10_set_output_transfer_func()
    warn: variable dereferenced before check 'stream' (see line 1875)(CVE-2024-27044)

    In the Linux kernel, the following vulnerability has been resolved: init/main.c: Fix potential
    static_command_line memory overflow We allocate memory of size 'xlen + strlen(boot_command_line) + 1' for
    static_command_line, but the strings copied into static_command_line are extra_command_line and
    command_line, rather than extra_command_line and boot_command_line. When strlen(command_line) 
    strlen(boot_command_line), static_command_line will overflow. This patch just recovers
    strlen(command_line) which was miss-consolidated with strlen(boot_command_line) in the commit f5c7310ac73e
    ('init/main: add checks for the return value of memblock_alloc*()')(CVE-2024-26988)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix a use-after-free There
    are two .exit_cmd_priv implementations. Both implementations use resources associated with the SCSI host.
    Make sure that these resources are still available when .exit_cmd_priv is called by waiting inside
    scsi_remove_host() until the tag set has been freed.(CVE-2022-48666)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Guard stack limits against 32bit
    overflow This patch promotes the arithmetic around checking stack bounds to be done in the 64-bit domain,
    instead of the current 32bit. The arithmetic implies adding together a 64-bit register with a int offset.
    The register was checked to be below 129 when it was variable, but not when it was fixed. The offset
    either comes from an instruction (in which case it is 16 bit), from another register (in which case the
    caller checked it to be below 129 [1]), or from the size of an argument to a kfunc (in which case it
    can be a u32 [2]). Between the register being inconsistently checked to be below 129, and the offset
    being up to an u32, it appears that we were open to overflowing the `int`s which were currently used for
    arithmetic.(CVE-2023-52676)

    In the Linux kernel, the following vulnerability has been resolved: cpumap: Zero-initialise xdp_rxq_info
    struct before running XDP program When running an XDP program that is attached to a cpumap entry, we don't
    initialise the xdp_rxq_info data structure being used in the xdp_buff that backs the XDP program
    invocation. Tobias noticed that this leads to random values being returned as the xdp_md-rx_queue_index
    value for XDP programs running in a cpumap. This means we're basically returning the contents of the
    uninitialised memory, which is bad. Fix this by zero-initialising the rxq data structure before running
    the XDP program.(CVE-2024-27431)

    In the Linux kernel, the following vulnerability has been resolved: ext4: fix corruption during on-line
    resize We observed a corruption during on-line resize of a file system that is larger than 16 TiB with 4k
    block size. With having more then 2^32 blocks resize_inode is turned off by default by mke2fs. The issue
    can be reproduced on a smaller file system for convenience by explicitly turning off resize_inode. An on-
    line resize across an 8 GiB boundary (the size of a meta block group in this setup) then leads to a
    corruption: dev=/dev/some_dev # should be = 16 GiB mkdir -p /corruption /sbin/mke2fs -t ext4 -b
    4096 -O ^resize_inode $dev $((2 * 2**21 - 2**15)) mount -t ext4 $dev /corruption dd if=/dev/zero bs=4096
    of=/corruption/test count=$((2*2**21 - 4*2**15)) sha1sum /corruption/test #
    79d2658b39dcfd77274e435b0934028adafaab11 /corruption/test /sbin/resize2fs $dev $((2*2**21)) # drop page
    cache to force reload the block from disk echo 1  /proc/sys/vm/drop_caches sha1sum /corruption/test #
    3c2abc63cbf1a94c9e6977e0fbd72cd832c4d5c3 /corruption/test 2^21 = 2^15*2^6 equals 8 GiB whereof 2^15 is the
    number of blocks per block group and 2^6 are the number of block groups that make a meta block group. The
    last checksum might be different depending on how the file is laid out across the physical blocks. The
    actual corruption occurs at physical block 63*2^15 = 2064384 which would be the location of the backup of
    the meta block group's block descriptor. During the on-line resize the file system will be converted to
    meta_bg starting at s_first_meta_bg which is 2 in the example - meaning all block groups after 16 GiB.
    However, in ext4_flex_group_add we might add block groups that are not part of the first meta block group
    yet. In the reproducer we achieved this by substracting the size of a whole block group from the point
    where the meta block group would start. This must be considered when updating the backup block group
    descriptors to follow the non-meta_bg layout. The fix is to add a test whether the group to add is already
    part of the meta block group or not.(CVE-2024-35807)

    In the Linux kernel, the following vulnerability has been resolved: io_uring: drop any code related to
    SCM_RIGHTS This is dead code after we dropped support for passing io_uring fds over SCM_RIGHTS, get rid of
    it.(CVE-2023-52656)

    In the Linux kernel, the following vulnerability has been resolved: ARM: 9359/1: flush: check if the folio
    is reserved for no-mapping addresses Since commit a4d5613c4dc6 ('arm: extend pfn_valid to take into
    account freed memory map alignment') changes the semantics of pfn_valid() to check presence of the memory
    map for a PFN.(CVE-2024-26947)

    In the Linux kernel, the following vulnerability has been resolved: media: bttv: fix use after free error
    due to btv-timeout timer There may be some a race condition between timer function bttv_irq_timeout and
    bttv_remove. The timer is setup in probe and there is no timer_delete operation in remove function. When
    it hit kfree btv, the function might still be invoked, which will cause use after free bug. This bug is
    found by static analysis, it may be false positive. Fix it by adding del_timer_sync invoking to the remove
    function. cpu0 cpu1 bttv_probe -timer_setup -bttv_set_dma -mod_timer; bttv_remove -kfree(btv);
    -bttv_irq_timeout -USE btv(CVE-2023-52847)

    In the Linux kernel, the following vulnerability has been resolved: calipso: fix memory leak in
    netlbl_calipso_add_pass() If IPv6 support is disabled at boot (ipv6.disable=1), the calipso_init() -
    netlbl_calipso_ops_register() function isn't called, and the netlbl_calipso_ops_get() function always
    returns NULL. In this case, the netlbl_calipso_add_pass() function allocates memory for the doi_def
    variable but doesn't free it with the calipso_doi_free().(CVE-2023-52698)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: release mutex
    after nft_gc_seq_end from abort path The commit mutex should not be released during the critical section
    between nft_gc_seq_begin() and nft_gc_seq_end(), otherwise, async GC worker could collect expired objects
    and get the released commit lock within the same GC sequence. nf_tables_module_autoload() temporarily
    releases the mutex to load module dependencies, then it goes back to replay the transaction again. Move it
    at the end of the abort phase after nft_gc_seq_end() is called.(CVE-2024-26925)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_pipapo: do not free
    live element Pablo reports a crash with large batches of elements with a back-to-back add/remove pattern.
    Quoting Pablo: add_elem('00000000') timeout 100 ms ... add_elem('0000000X') timeout 100 ms
    del_elem('0000000X') ---------------- delete one that was just added ... add_elem('00005000') timeout
    100 ms 1) nft_pipapo_remove() removes element 0000000X Then, KASAN shows a splat. Looking at the remove
    function there is a chance that we will drop a rule that maps to a non-deactivated element. Removal
    happens in two steps, first we do a lookup for key k and return the to-be-removed element and mark it as
    inactive in the next generation. Then, in a second step, the element gets removed from the set/map. The
    _remove function does not work correctly if we have more than one element that share the same key. This
    can happen if we insert an element into a set when the set already holds an element with same key, but the
    element mapping to the existing key has timed out or is not active in the next generation. In such case
    its possible that removal will unmap the wrong element. If this happens, we will leak the non-deactivated
    element, it becomes unreachable. The element that got deactivated (and will be freed later) will remain
    reachable in the set data structure, this can result in a crash when such an element is retrieved during
    lookup (stale pointer). Add a check that the fully matching key does in fact map to the element that we
    have marked as inactive in the deactivation step. If not, we need to continue searching. Add a bug/warn
    trap at the end of the function as well, the remove function must not ever be called with an
    invisible/unreachable/non-existent element. v2: avoid uneeded temporary variable (Stefano)(CVE-2024-26924)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: LPIT: Avoid u32 multiplication
    overflow In lpit_update_residency() there is a possibility of overflow in multiplication, if tsc_khz is
    large enough ( UINT_MAX/1000). Change multiplication to mul_u32_u32(). Found by Linux Verification
    Center (linuxtesting.org) with SVACE.(CVE-2023-52683)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: video: check for error while
    searching for backlight device parent If acpi_get_parent() called in acpi_video_dev_register_backlight()
    fails, for example, because acpi_ut_acquire_mutex() fails inside acpi_get_parent), this can lead to
    incorrect (uninitialized) acpi_parent handle being passed to acpi_get_pci_dev() for detecting the parent
    pci device. Check acpi_get_parent() result and set parent device only in case of success. Found by Linux
    Verification Center (linuxtesting.org) with SVACE.(CVE-2023-52693)

    In the Linux kernel, the following vulnerability has been resolved: ipvlan: Fix out-of-bound bugs caused
    by unset skb-mac_header If an AF_PACKET socket is used to send packets through ipvlan and the default
    xmit function of the AF_PACKET socket is changed from dev_queue_xmit() to packet_direct_xmit() via
    setsockopt() with the option name of PACKET_QDISC_BYPASS, the skb-mac_header may not be reset and
    remains as the initial value of 65535, this may trigger slab-out-of-bounds bugs as following: UG: KASAN:
    slab-out-of-bounds in ipvlan_xmit_mode_l2(CVE-2022-48651)

    In the Linux kernel, the following vulnerability has been resolved: i40e: Do not allow untrusted VF to
    remove administratively set MAC Currently when PF administratively sets VF's MAC address and the VF is put
    down (VF tries to delete all MACs) then the MAC is removed from MAC filters and primary VF MAC is zeroed.
    Do not allow untrusted VF to remove primary MAC when it was set administratively by PF.(CVE-2024-26830)

    In the Linux kernel, the following vulnerability has been resolved: selinux: avoid dereference of garbage
    after mount failure In case kern_mount() fails and returns an error pointer return in the error branch
    instead of continuing and dereferencing the error pointer. While on it drop the never read static variable
    selinuxfs_mount.(CVE-2024-35904)

    In the Linux kernel, the following vulnerability has been resolved: drm/i915/gt: Reset queue_priority_hint
    on parking Originally, with strict in order execution, we could complete execution only when the queue was
    empty. Preempt-to-busy allows replacement of an active request that may complete before the preemption is
    processed by HW. If that happens, the request is retired from the queue, but the queue_priority_hint
    remains set, preventing direct submission until after the next CS interrupt is processed. This preempt-to-
    busy race can be triggered by the heartbeat, which will also act as the power-management barrier and upon
    completion allow us to idle the HW. We may process the completion of the heartbeat, and begin parking the
    engine before the CS event that restores the queue_priority_hint, causing us to fail the assertion that it
    is MIN.(CVE-2024-26937)

    In the Linux kernel, the following vulnerability has been resolved: thermal/int340x_thermal: handle
    data_vault when the value is ZERO_SIZE_PTR In some case, the GDDV returns a package with a buffer which
    has zero length. It causes that kmemdup() returns ZERO_SIZE_PTR (0x10). Then the data_vault_read() got
    NULL point dereference problem when accessing the 0x10 value in data_vault. [ 71.024560] BUG: kernel NULL
    pointer dereference, address: 0000000000000010 This patch uses ZERO_OR_NULL_PTR() for checking
    ZERO_SIZE_PTR or NULL value in data_vault.(CVE-2022-48703)

    In the Linux kernel, the following vulnerability has been resolved: gfs2: ignore negated quota changes
    When lots of quota changes are made, there may be cases in which an inode's quota information is increased
    and then decreased, such as when blocks are added to a file, then deleted from it. If the timing is right,
    function do_qc can add pending quota changes to a transaction, then later, another call to do_qc can
    negate those changes, resulting in a net gain of 0. The quota_change information is recorded in the qc
    buffer (and qd element of the inode as well). The buffer is added to the transaction by the first call to
    do_qc, but a subsequent call changes the value from non-zero back to zero. At that point it's too late to
    remove the buffer_head from the transaction. Later, when the quota sync code is called, the zero-change qd
    element is discovered and flagged as an assert warning. If the fs is mounted with errors=panic, the kernel
    will panic. This is usually seen when files are truncated and the quota changes are negated by
    punch_hole/truncate which uses gfs2_quota_hold and gfs2_quota_unhold rather than block allocations that
    use gfs2_quota_lock and gfs2_quota_unlock which automatically do quota sync. This patch solves the problem
    by adding a check to qd_check_sync such that net-zero quota changes already added to the transaction are
    no longer deemed necessary to be synced, and skipped. In this case references are taken for the qd and the
    slot from do_qc so those need to be put. The normal sequence of events for a normal non-zero quota change
    is as follows: gfs2_quota_change do_qc qd_hold slot_hold Later, when the changes are to be synced:
    gfs2_quota_sync qd_fish qd_check_sync gets qd ref via lockref_get_not_dead do_sync do_qc(QC_SYNC) qd_put
    lockref_put_or_lock qd_unlock qd_put lockref_put_or_lock In the net-zero change case, we add a check to
    qd_check_sync so it puts the qd and slot references acquired in gfs2_quota_change and skip the unneeded
    sync.(CVE-2023-52759)

    In the Linux kernel, the following vulnerability has been resolved: pstore/platform: Add check for kstrdup
    Add check for the return value of kstrdup() and return the error if it fails in order to avoid NULL
    pointer dereference.(CVE-2023-52869)

    In the Linux kernel, the following vulnerability has been resolved: tcp: Use refcount_inc_not_zero() in
    tcp_twsk_unique(). Anderson Nascimento reported a use-after-free splat in tcp_twsk_unique() with nice
    analysis. Since commit ec94c2696f0b ('tcp/dccp: avoid one atomic operation for timewait hashdance'),
    inet_twsk_hashdance() sets TIME-WAIT socket's sk_refcnt after putting it into ehash and releasing the
    bucket lock. Thus, there is a small race window where other threads could try to reuse the port during
    connect() and call sock_hold() in tcp_twsk_unique() for the TIME-WAIT socket with zero refcnt. If that
    happens, the refcnt taken by tcp_twsk_unique() is overwritten and sock_put() will cause underflow,
    triggering a real use-after-free somewhere else. To avoid the use-after-free, we need to use
    refcount_inc_not_zero() in tcp_twsk_unique() and give up on reusing the port if it returns
    false.(CVE-2024-36904)

    In the Linux kernel, the following vulnerability has been resolved: net: ena: Fix incorrect descriptor
    free behavior ENA has two types of TX queues: - queues which only process TX packets arriving from the
    network stack - queues which only process TX packets forwarded to it by XDP_REDIRECT or XDP_TX
    instructions The ena_free_tx_bufs() cycles through all descriptors in a TX queue and unmaps + frees every
    descriptor that hasn't been acknowledged yet by the device (uncompleted TX transactions). The function
    assumes that the processed TX queue is necessarily from the first category listed above and ends up using
    napi_consume_skb() for descriptors belonging to an XDP specific queue. This patch solves a bug in which,
    in case of a VF reset, the descriptors aren't freed correctly, leading to crashes.(CVE-2024-35958)

    In the Linux kernel, the following vulnerability has been resolved: thermal: core: prevent potential
    string overflow The dev-id value comes from ida_alloc() so it's a number between zero and INT_MAX. If
    it's too high then these sprintf()s will overflow.(CVE-2023-52868)

    In the Linux kernel, the following vulnerability has been resolved: media: gspca: cpia1: shift-out-of-
    bounds in set_flicker Syzkaller reported the following issue: UBSAN: shift-out-of-bounds in
    drivers/media/usb/gspca/cpia1.c:1031:27 shift exponent 245 is too large for 32-bit type 'int' When the
    value of the variable 'sd-params.exposure.gain' exceeds the number of bits in an integer, a shift-out-
    of-bounds error is reported. It is triggered because the variable 'currentexp' cannot be left-shifted by
    more than the number of bits in an integer. In order to avoid invalid range during left-shift, the
    conditional expression is added.(CVE-2023-52764)

    In the Linux kernel, the following vulnerability has been resolved: ceph: blocklist the kclient when
    receiving corrupted snap trace When received corrupted snap trace we don't know what exactly has happened
    in MDS side. And we shouldn't continue IOs and metadatas access to MDS, which may corrupt or get incorrect
    contents. This patch will just block all the further IO/MDS requests immediately and then evict the
    kclient itself. The reason why we still need to evict the kclient just after blocking all the further IOs
    is that the MDS could revoke the caps faster.(CVE-2023-52732)

    In the Linux kernel, the following vulnerability has been resolved: perf: hisi: Fix use-after-free when
    register pmu fails When we fail to register the uncore pmu, the pmu context may not been allocated. The
    error handing will call cpuhp_state_remove_instance() to call uncore pmu offline callback, which migrate
    the pmu context. Since that's liable to lead to some kind of use-after-free. Use
    cpuhp_state_remove_instance_nocalls() instead of cpuhp_state_remove_instance() so that the notifiers don't
    execute after the PMU device has been failed to register.(CVE-2023-52859)

    In the Linux kernel, the following vulnerability has been resolved: block: prevent division by zero in
    blk_rq_stat_sum() The expression dst-nr_samples + src-nr_samples may have zero value on overflow. It
    is necessary to add a check to avoid division by zero. Found by Linux Verification Center
    (linuxtesting.org) with Svace.(CVE-2024-35925)

    In the Linux kernel, the following vulnerability has been resolved: scsi: hisi_sas: Set debugfs_dir
    pointer to NULL after removing debugfs If init debugfs failed during device registration due to memory
    allocation failure, debugfs_remove_recursive() is called, after which debugfs_dir is not set to NULL.
    debugfs_remove_recursive() will be called again during device removal. As a result, illegal pointer is
    accessed.(CVE-2023-52808)

    In the Linux kernel, the following vulnerability has been resolved: smb: client: fix use-after-free bug in
    cifs_debug_data_proc_show() Skip SMB sessions that are being teared down (e.g. @ses-ses_status ==
    SES_EXITING) in cifs_debug_data_proc_show() to avoid use-after-free in @ses. This fixes the following GPF
    when reading from /proc/fs/cifs/DebugData while mounting and umounting [ 816.251274] general protection
    fault, probably for non-canonical address 0x6b6b6b6b6b6b6d81: 0000 [#1] PREEMPT SMP NOPTI ... [
    816.260138] Call Trace: [ 816.260329] TASK [ 816.260499] ? die_addr+0x36/0x90 [ 816.260762] ?
    exc_general_protection+0x1b3/0x410 [ 816.261126] ? asm_exc_general_protection+0x26/0x30 [ 816.261502] ?
    cifs_debug_tcon+0xbd/0x240 [cifs] [ 816.261878] ? cifs_debug_tcon+0xab/0x240 [cifs] [ 816.262249]
    cifs_debug_data_proc_show+0x516/0xdb0 [cifs] [ 816.262689] ? seq_read_iter+0x379/0x470 [ 816.262995]
    seq_read_iter+0x118/0x470 [ 816.263291] proc_reg_read_iter+0x53/0x90 [ 816.263596] ?
    srso_alias_return_thunk+0x5/0x7f [ 816.263945] vfs_read+0x201/0x350 [ 816.264211] ksys_read+0x75/0x100 [
    816.264472] do_syscall_64+0x3f/0x90 [ 816.264750] entry_SYSCALL_64_after_hwframe+0x6e/0xd8 [ 816.265135]
    RIP: 0033:0x7fd5e669d381(CVE-2023-52752)

    In the Linux kernel, the following vulnerability has been resolved: cpu/hotplug: Don't offline the last
    non-isolated CPU If a system has isolated CPUs via the 'isolcpus=' command line parameter, then an attempt
    to offline the last housekeeping CPU will result in a WARN_ON() when rebuilding the scheduler domains and
    a subsequent panic due to and unhandled empty CPU mas in partition_sched_domains_locked().
    cpuset_hotplug_workfn() rebuild_sched_domains_locked() ndoms = generate_sched_domains(doms, attr);
    cpumask_and(doms[0], top_cpuset.effective_cpus, housekeeping_cpumask(HK_FLAG_DOMAIN)); Thus results in an
    empty CPU mask which triggers the warning and then the subsequent crash: WARNING: CPU: 4 PID: 80 at
    kernel/sched/topology.c:2366 build_sched_domains+0x120c/0x1408 Call trace:
    build_sched_domains+0x120c/0x1408 partition_sched_domains_locked+0x234/0x880
    rebuild_sched_domains_locked+0x37c/0x798 rebuild_sched_domains+0x30/0x58 cpuset_hotplug_workfn+0x2a8/0x930
    Unable to handle kernel paging request at virtual address fffe80027ab37080
    partition_sched_domains_locked+0x318/0x880 rebuild_sched_domains_locked+0x37c/0x798 Aside of the resulting
    crash, it does not make any sense to offline the last last housekeeping CPU. Prevent this by masking out
    the non-housekeeping CPUs when selecting a target CPU for initiating the CPU unplug operation via the work
    queue.(CVE-2023-52831)

    In the Linux kernel, the following vulnerability has been resolved: mm/hugetlb: fix missing hugetlb_lock
    for resv uncharge There is a recent report on UFFDIO_COPY over hugetlb:
    https://lore.kernel.org/all/000000000000ee06de0616177560@google.com/ 350:
    lockdep_assert_held(hugetlb_lock); Should be an issue in hugetlb but triggered in an userfault context,
    where it goes into the unlikely path where two threads modifying the resv map together. Mike has a fix in
    that path for resv uncharge but it looks like the locking criteria was overlooked:
    hugetlb_cgroup_uncharge_folio_rsvd() will update the cgroup pointer, so it requires to be called with the
    lock held.(CVE-2024-36000)

    In the Linux kernel, the following vulnerability has been resolved: dma-direct: Leak pages on
    dma_set_decrypted() failure On TDX it is possible for the untrusted host to cause set_memory_encrypted()
    or set_memory_decrypted() to fail such that an error is returned and the resulting memory is shared.
    Callers need to take care to handle these errors to avoid returning decrypted (shared) memory to the page
    allocator, which could lead to functional or security issues. DMA could free decrypted/shared pages if
    dma_set_decrypted() fails. This should be a rare case. Just leak the pages in this case instead of freeing
    them.(CVE-2024-35939)

    In the Linux kernel, the following vulnerability has been resolved: x86/mm/pat: fix VM_PAT handling in COW
    mappings PAT handling won't do the right thing in COW mappings: the first PTE (or, in fact, all PTEs) can
    be replaced during write faults to point at anon folios. Reliably recovering the correct PFN and cachemode
    using follow_phys() from PTEs will not work in COW mappings. Using follow_phys(), we might just get the
    address+protection of the anon folio (which is very wrong), or fail on swap/nonswap entries, failing
    follow_phys() and triggering a WARN_ON_ONCE() in untrack_pfn() and track_pfn_copy(), not properly calling
    free_pfn_range(). In free_pfn_range(), we either wouldn't call memtype_free() or would call it with the
    wrong range, possibly leaking memory. To fix that, let's update follow_phys() to refuse returning anon
    folios, and fallback to using the stored PFN inside vma-vm_pgoff for COW mappings if we run into that.
    We will now properly handle untrack_pfn() with COW mappings, where we don't need the cachemode. We'll have
    to fail fork()-track_pfn_copy() if the first page was replaced by an anon folio, though: we'd have to
    store the cachemode in the VMA to make this work, likely growing the VMA size. For now, lets keep it
    simple and let track_pfn_copy() just fail in that case: it would have failed in the past with swap/nonswap
    entries already, and it would have done the wrong thing with anon folios. Simple reproducer to trigger the
    WARN_ON_ONCE() in untrack_pfn().(CVE-2024-35877)

    In the Linux kernel, the following vulnerability has been resolved: x86/mm/pat: fix VM_PAT handling in COW
    mappings PAT handling won't do the right thing in COW mappings: the first PTE (or, in fact, all PTEs) can
    be replaced during write faults to point at anon folios. Reliably recovering the correct PFN and cachemode
    using follow_phys() from PTEs will not work in COW mappings. Using follow_phys(), we might just get the
    address+protection of the anon folio (which is very wrong), or fail on swap/nonswap entries, failing
    follow_phys() and triggering a WARN_ON_ONCE() in untrack_pfn() and track_pfn_copy(), not properly calling
    free_pfn_range(). In free_pfn_range(), we either wouldn't call memtype_free() or would call it with the
    wrong range, possibly leaking memory. To fix that, let's update follow_phys() to refuse returning anon
    folios, and fallback to using the stored PFN inside vma-vm_pgoff for COW mappings if we run into that.
    We will now properly handle untrack_pfn() with COW mappings, where we don't need the cachemode. We'll have
    to fail fork()-track_pfn_copy() if the first page was replaced by an anon folio, though: we'd have to
    store the cachemode in the VMA to make this work, likely growing the VMA size. For now, lets keep it
    simple and let track_pfn_copy() just fail in that case: it would have failed in the past with swap/nonswap
    entries already, and it would have done the wrong thing with anon folios. Simple reproducer to trigger the
    WARN_ON_ONCE() in untrack_pfn()(CVE-2023-52843)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_flow_offload: reset dst
    in route object after setting up flow dst is transferred to the flow object, route object does not own it
    anymore. Reset dst in route object, otherwise if flow_offload_add() fails, error path releases dst twice,
    leading to a refcount underflow.(CVE-2024-27403)

    In the Linux kernel, the following vulnerability has been resolved: ipv4: check for NULL idev in
    ip_route_use_hint() syzbot was able to trigger a NULL deref in fib_validate_source() in an old tree [1].
    It appears the bug exists in latest trees. All calls to __in_dev_get_rcu() must be checked for a NULL
    result. [1] general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] SMP
    KASAN KASAN: null-ptr-deref in range[0x0000000000000000-0x0000000000000007(CVE-2024-36008)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fix potential null pointer
    derefernce The amdgpu_ras_get_context may return NULL if device not support ras feature, so add check
    before using.(CVE-2023-52814)

    In the Linux kernel, the following vulnerability has been resolved: riscv: Check if the code to patch lies
    in the exit section Otherwise we fall through to vmalloc_to_page() which panics since the address does not
    lie in the vmalloc region.(CVE-2023-52677)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix warning
    during rehash As previously explained, the rehash delayed work migrates filters from one region to
    another. This is done by iterating over all chunks (all the filters with the same priority) in the region
    and in each chunk iterating over all the filters. When the work runs out of credits it stores the current
    chunk and entry as markers in the per-work context so that it would know where to resume the migration
    from the next time the work is scheduled. Upon error, the chunk marker is reset to NULL, but without
    resetting the entry markers despite being relative to it. This can result in migration being resumed from
    an entry that does not belong to the chunk being migrated. In turn, this will eventually lead to a chunk
    being iterated over as if it is an entry. Because of how the two structures happen to be defined, this
    does not lead to KASAN splats, but to warnings such as [1]. Fix by creating a helper that resets all the
    markers and call it from all the places the currently only reset the chunk marker. For good measures also
    call it when starting a completely new rehash. Add a warning to avoid future cases.(CVE-2024-36007)

    In the Linux kernel, the following vulnerability has been resolved: pinctrl: core: delete incorrect free
    in pinctrl_enable() The 'pctldev' struct is allocated in devm_pinctrl_register_and_init(). It's a devm_
    managed pointer that is freed by devm_pinctrl_dev_release(), so freeing it in pinctrl_enable() will lead
    to a double free. The devm_pinctrl_dev_release() function frees the pindescs and destroys the mutex as
    well.(CVE-2024-36940)

    In the Linux kernel, the following vulnerability has been resolved: blk-iocost: do not WARN if iocg was
    already offlined In iocg_pay_debt(), warn is triggered if 'active_list' is empty, which is intended to
    confirm iocg is active when it has debt. However, warn can be triggered during a blkcg or disk removal, if
    iocg_waitq_timer_fn() is run at that time: WARNING: CPU: 0 PID: 2344971 at block/blk-iocost.c:1402
    iocg_pay_debt+0x14c/0x190 Call trace: iocg_pay_debt+0x14c/0x190 iocg_kick_waitq+0x438/0x4c0
    iocg_waitq_timer_fn+0xd8/0x130 __run_hrtimer+0x144/0x45c __hrtimer_run_queues+0x16c/0x244
    hrtimer_interrupt+0x2cc/0x7b0 The warn in this situation is meaningless. Since this iocg is being removed,
    the state of the 'active_list' is irrelevant, and 'waitq_timer' is canceled after removing 'active_list'
    in ioc_pd_free(), which ensures iocg is freed after iocg_waitq_timer_fn() returns. Therefore, add the
    check if iocg was already offlined to avoid warn when removing a blkcg or disk.(CVE-2024-36908)

    In the Linux kernel, the following vulnerability has been resolved: gpiolib: cdev: fix uninitialised kfifo
    If a line is requested with debounce, and that results in debouncing in software, and the line is
    subsequently reconfigured to enable edge detection then the allocation of the kfifo to contain edge events
    is overlooked. This results in events being written to and read from an uninitialised kfifo. Read events
    are returned to userspace. Initialise the kfifo in the case where the software debounce is already
    active.(CVE-2024-36898)

    In the Linux kernel, the following vulnerability has been resolved: gpiolib: cdev: Fix use after free in
    lineinfo_changed_notify The use-after-free issue occurs as follows: when the GPIO chip device file is
    being closed by invoking gpio_chrdev_release(), watched_lines is freed by bitmap_free(), but the
    unregistration of lineinfo_changed_nb notifier chain failed due to waiting write rwsem. Additionally, one
    of the GPIO chip's lines is also in the release process and holds the notifier chain's read rwsem.
    Consequently, a race condition leads to the use-after-free of watched_lines. Here is the typical stack
    when issue happened: [free] gpio_chrdev_release() -- bitmap_free(cdev-watched_lines) -- freed
    -- blocking_notifier_chain_unregister() -- down_write(nh-rwsem) -- waiting rwsem --
    __down_write_common() -- rwsem_down_write_slowpath() -- schedule_preempt_disabled() -- schedule()
    [use] st54spi_gpio_dev_release() -- gpio_free() -- gpiod_free() -- gpiod_free_commit() --
    gpiod_line_state_notify() -- blocking_notifier_call_chain() -- down_read(nh-rwsem); -- held
    rwsem -- notifier_call_chain() -- lineinfo_changed_notify() -- test_bit(xxxx, cdev-
    watched_lines) -- use after free The side effect of the use-after-free issue is that a GPIO line
    event is being generated for userspace where it shouldn't. However, since the chrdev is being closed,
    userspace won't have the chance to read that event anyway. To fix the issue, call the bitmap_free()
    function after the unregistration of lineinfo_changed_nb notifier chain.(CVE-2024-36899)

    In the Linux kernel, the following vulnerability has been resolved: smb: client: fix UAF in
    smb2_reconnect_server() The UAF bug is due to smb2_reconnect_server() accessing a session that is already
    being teared down by another thread that is executing __cifs_put_smb_ses(). This can happen when (a) the
    client has connection to the server but no session or (b) another thread ends up setting @ses-
    ses_status again to something different than SES_EXITING. To fix this, we need to make sure to
    unconditionally set @ses-ses_status to SES_EXITING and prevent any other threads from setting a new
    status while we're still tearing it down.(CVE-2024-35870)

    In the Linux kernel, the following vulnerability has been resolved: usb: typec: ucsi: Limit read size on
    v1.2 Between UCSI 1.2 and UCSI 2.0, the size of the MESSAGE_IN region was increased from 16 to 256. In
    order to avoid overflowing reads for older systems, add a mechanism to use the read UCSI version to
    truncate read sizes on UCSI v1.2.(CVE-2024-35924)

    In the Linux kernel, the following vulnerability has been resolved: smb: client: fix potential deadlock
    when releasing mids All release_mid() callers seem to hold a reference of @mid so there is no need to call
    kref_put(mid-refcount, __release_mid) under @server-mid_lock spinlock. If they don't, then an
    use-after-free bug would have occurred anyways. By getting rid of such spinlock also fixes a potential
    deadlock as shown below CPU 0 CPU 1 ------------------------------------------------------------------
    cifs_demultiplex_thread() cifs_debug_data_proc_show() release_mid() spin_lock(server-mid_lock);
    spin_lock(cifs_tcp_ses_lock) spin_lock(server-mid_lock) __release_mid() smb2_find_smb_tcon()
    spin_lock(cifs_tcp_ses_lock) *deadlock*(CVE-2023-52757)

    In the Linux kernel, the following vulnerability has been resolved: nouveau: fix instmem race condition
    around ptr stores Running a lot of VK CTS in parallel against nouveau, once every few hours you might see
    something like this crash. BUG: kernel NULL pointer dereference, address: 0000000000000008 PGD
    8000000114e6e067 P4D 8000000114e6e067 PUD 109046067 PMD 0 Oops: 0000.(CVE-2024-26984)

    In the Linux kernel, the following vulnerability has been resolved: usb: typec: altmodes/displayport:
    create sysfs nodes as driver's default device attribute group The DisplayPort driver's sysfs nodes may be
    present to the userspace before typec_altmode_set_drvdata() completes in dp_altmode_probe. This means that
    a sysfs read can trigger a NULL pointer error by deferencing dp-hpd in hpd_show or dp-lock in
    pin_assignment_show, as dev_get_drvdata() returns NULL in those cases. Remove manual sysfs node creation
    in favor of adding attribute group as default for devices bound to the driver. The ATTRIBUTE_GROUPS()
    macro is not used here otherwise the path to the sysfs nodes is no longer compliant with the
    ABI.(CVE-2024-35790)

    In the Linux kernel, the following vulnerability has been resolved: block: fix overflow in
    blk_ioctl_discard() There is no check for overflow of 'start + len' in blk_ioctl_discard(). Hung task
    occurs if submit an discard ioctl with the following param: start = 0x80000000000ff000, len =
    0x8000000000fff000; Add the overflow validation now.(CVE-2024-36917)

    In the Linux kernel, the following vulnerability has been resolved: keys: Fix overwrite of key expiration
    on instantiation The expiry time of a key is unconditionally overwritten during instantiation, defaulting
    to turn it permanent. This causes a problem for DNS resolution as the expiration set by user-space is
    overwritten to TIME64_MAX, disabling further DNS updates. Fix this by restoring the condition that
    key_set_expiry is only called when the pre-parser sets a specific expiry.(CVE-2024-36031)

    In the Linux kernel, the following vulnerability has been resolved: blk-iocost: avoid out of bounds shift
    UBSAN catches undefined behavior in blk-iocost, where sometimes iocg-delay is shifted right by a number
    that is too large, resulting in undefined behavior on some architectures.(CVE-2024-36916)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd: Fix UBSAN array-index-out-of-
    bounds for SMU7 For pptable structs that use flexible array sizes, use flexible arrays.(CVE-2023-52818)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: fix a double-free in
    arfs_create_groups When `in` allocated by kvzalloc fails, arfs_create_groups will free ft-g and return
    an error. However, arfs_create_table, the only caller of arfs_create_groups, will hold this error and call
    to mlx5e_destroy_flow_table, in which the ft-g will be freed again.(CVE-2024-35835)

    In the Linux kernel, the following vulnerability has been resolved: KVM: SVM: Flush pages under kvm-
    lock to fix UAF in svm_register_enc_region() Do the cache flush of converted pages in
    svm_register_enc_region() before dropping kvm-lock to fix use-after-free issues where region and/or its
    array of pages could be freed by a different task, e.g. if userspace has __unregister_enc_region_locked()
    already queued up for the region. Note, the 'obvious' alternative of using local variables doesn't fully
    resolve the bug, as region-pages is also dynamically allocated. I.e. the region structure itself would
    be fine, but region-pages could be freed. Flushing multiple pages under kvm-lock is unfortunate, but
    the entire flow is a rare slow path, and the manual flush is only needed on CPUs that lack coherency for
    encrypted memory.(CVE-2024-35791)

    In the Linux kernel, the following vulnerability has been resolved: irqchip/gic-v3-its: Prevent double
    free on error The error handling path in its_vpe_irq_domain_alloc() causes a double free when
    its_vpe_init() fails after successfully allocating at least one interrupt. This happens because
    its_vpe_irq_domain_free() frees the interrupts along with the area bitmap and the vprop_page and
    its_vpe_irq_domain_alloc() subsequently frees the area bitmap and the vprop_page again. Fix this by
    unconditionally invoking its_vpe_irq_domain_free() which handles all cases correctly and by removing the
    bitmap/vprop_page freeing from its_vpe_irq_domain_alloc().(CVE-2024-35847)

    n the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix incorrect
    list API usage Both the function that migrates all the chunks within a region and the function that
    migrates all the entries within a chunk call list_first_entry() on the respective lists without checking
    that the lists are not empty. This is incorrect usage of the API, which leads to the following warning
    [1]. Fix by returning if the lists are empty as there is nothing to migrate in this
    case.(CVE-2024-36006)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Avoid NULL
    dereference of timing generator [Why  How] Check whether assigned timing generator is NULL or not
    before accessing its funcs to prevent NULL dereference.(CVE-2023-52753)

    In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: don't return unset
    power in ieee80211_get_tx_power() We can get a UBSAN warning if ieee80211_get_tx_power() returns the
    INT_MIN value mac80211 internally uses for 'unset power level'.(CVE-2023-52832)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Properly link new fs rules
    into the tree Previously, add_rule_fg would only add newly created rules from the handle into the tree
    when they had a refcount of 1. On the other hand, create_flow_handle tries hard to find and reference
    already existing identical rules instead of creating new ones. These two behaviors can result in a
    situation where create_flow_handle 1) creates a new rule and references it, then 2) in a subsequent step
    during the same handle creation references it again, resulting in a rule with a refcount of 2 that is not
    linked into the tree, will have a NULL parent and root and will result in a crash when the flow group is
    deleted because del_sw_hw_rule, invoked on rule deletion, assumes node-parent is != NULL. This happened
    in the wild, due to another bug related to incorrect handling of duplicate pkt_reformat ids, which lead to
    the code in create_flow_handle incorrectly referencing a just-added rule in the same flow handle,
    resulting in the problem described above. Full details are at [1]. This patch changes add_rule_fg to add
    new rules without parents into the tree, properly initializing them and avoiding the crash. This makes it
    more consistent with how rules are added to an FTE in create_flow_handle.(CVE-2024-35960)

    In the Linux kernel, the following vulnerability has been resolved: scsi: lpfc: Release hbalock before
    calling lpfc_worker_wake_up() lpfc_worker_wake_up() calls the lpfc_work_done() routine, which takes the
    hbalock. Thus, lpfc_worker_wake_up() should not be called while holding the hbalock to avoid potential
    deadlock.(CVE-2024-36924)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: Fix potential uninit-value
    access in __ip6_make_skb() As it was done in commit fc1092f51567 ('ipv4: Fix uninit-value access in
    __ip_make_skb()') for IPv4, check FLOWI_FLAG_KNOWN_NH on fl6-flowi6_flags instead of testing HDRINCL on
    the socket to avoid a race condition which causes uninit-value access.(CVE-2024-36903)

    In the Linux kernel, the following vulnerability has been resolved: ppdev: Add an error check in
    register_device In register_device, the return value of ida_simple_get is unchecked, in witch
    ida_simple_get will use an invalid index value. To address this issue, index should be checked after
    ida_simple_get. When the index value is abnormal, a warning message should be printed, the port should be
    dropped, and the value should be recorded.(CVE-2024-36015)

    In the Linux kernel, the following vulnerability has been resolved: ppdev: Add an error check in
    register_device In register_device, the return value of ida_simple_get is unchecked, in witch
    ida_simple_get will use an invalid index value. To address this issue, index should be checked after
    ida_simple_get. When the index value is abnormal, a warning message should be printed, the port should be
    dropped, and the value should be recorded.(CVE-2022-48692)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Protect against int overflow for
    stack access size This patch re-introduces protection against the size of access to stack memory being
    negative; the access size can appear negative as a result of overflowing its signed int representation.
    This should not actually happen, as there are other protections along the way, but we should protect
    against it anyway. One code path was missing such protections (fixed in the previous patch in the series),
    causing out-of-bounds array accesses in check_stack_range_initialized(). This patch causes the
    verification of a program with such a non-sensical access size to fail. This check used to exist in a more
    indirect way, but was inadvertendly removed in a833a17aeac7.(CVE-2024-35905)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: prevent NULL dereference in
    ip6_output() According to syzbot, there is a chance that ip6_dst_idev() returns NULL in ip6_output(). Most
    places in IPv6 stack deal with a NULL idev just fine, but not here. syzbot reported: general protection
    fault, probably for non-canonical address 0xdffffc00000000bc: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-
    ptr-deref in range [0x00000000000005e0-0x00000000000005e7].(CVE-2024-36901)

    In the Linux kernel, the following vulnerability has been resolved: Bluetooth: SCO: Fix not validating
    setsockopt user input syzbot reported sco_sock_setsockopt() is copying data without checking user input
    length. BUG: KASAN: slab-out-of-bounds in copy_from_sockptr_offset include/linux/sockptr.h:49 [inline]
    BUG: KASAN: slab-out-of-bounds in copy_from_sockptr include/linux/sockptr.h:55 [inline] BUG: KASAN: slab-
    out-of-bounds in sco_sock_setsockopt+0xc0b/0xf90 net/bluetooth/sco.c:893 Read of size 4 at addr
    ffff88805f7b15a3 by task syz-executor.5/12578(CVE-2024-35967)

    In the Linux kernel, the following vulnerability has been resolved: erspan: make sure erspan_base_hdr is
    present in skb-head syzbot reported a problem in ip6erspan_rcv() [1] Issue is that ip6erspan_rcv() (and
    erspan_rcv()) no longer make sure erspan_base_hdr is present in skb linear part (skb-head) before
    getting @ver field from it. Add the missing pskb_may_pull() calls. v2: Reload iph pointer in erspan_rcv()
    after pskb_may_pull() because skb-head might have changed.(CVE-2024-35888)

    In the Linux kernel, the following vulnerability has been resolved: tcp: properly terminate timers for
    kernel sockets We had various syzbot reports about tcp timers firing after the corresponding netns has
    been dismantled. Fortunately Josef Bacik could trigger the issue more often, and could test a patch I
    wrote two years ago. When TCP sockets are closed, we call inet_csk_clear_xmit_timers() to 'stop' the
    timers. inet_csk_clear_xmit_timers() can be called from any context, including when socket lock is held.
    This is the reason it uses sk_stop_timer(), aka del_timer(). This means that ongoing timers might finish
    much later. For user sockets, this is fine because each running timer holds a reference on the socket, and
    the user socket holds a reference on the netns. For kernel sockets, we risk that the netns is freed before
    timer can complete, because kernel sockets do not hold reference on the netns. This patch adds
    inet_csk_clear_xmit_timers_sync() function that using sk_stop_timer_sync() to make sure all timers are
    terminated before the kernel socket is released. Modules using kernel sockets close them in their netns
    exit() handler. Also add sock_not_owned_by_me() helper to get LOCKDEP support :
    inet_csk_clear_xmit_timers_sync() must not be called while socket lock is held. It is very possible we can
    revert in the future commit 3a58f13a881e ('net: rds: acquire refcount on TCP sockets') which attempted to
    solve the issue in rds only. (net/smc/af_smc.c and net/mptcp/subflow.c have similar code) We probably can
    remove the check_net() tests from tcp_out_of_resources() and __tcp_close() in the future.(CVE-2024-35910)

    In the Linux kernel, the following vulnerability has been resolved: pipe: wakeup wr_wait after setting
    max_usage Commit c73be61cede5 ('pipe: Add general notification queue support') a regression was introduced
    that would lock up resized pipes under certain conditions. See the reproducer in [1]. The commit resizing
    the pipe ring size was moved to a different function, doing that moved the wakeup for pipe-wr_wait
    before actually raising pipe-max_usage. If a pipe was full before the resize occured it would result in
    the wakeup never actually triggering pipe_write. Set @max_usage and @nr_accounted before waking writers if
    this isn't a watch queue.(CVE-2023-52672)

    In the Linux kernel, the following vulnerability has been resolved: virtio-blk: fix implicit overflow on
    virtio_max_dma_size The following codes have an implicit conversion from size_t to u32: (u32)max_size =
    (size_t)virtio_max_dma_size(vdev); This may lead overflow, Ex (size_t)4G - (u32)0. Once
    virtio_max_dma_size() has a larger size than U32_MAX, use U32_MAX instead.(CVE-2023-52762)

    In the Linux kernel, the following vulnerability has been resolved: md/dm-raid: don't call
    md_reap_sync_thread() directly Currently md_reap_sync_thread() is called from raid_message() directly
    without holding 'reconfig_mutex', this is definitely unsafe because md_reap_sync_thread() can change many
    fields that is protected by 'reconfig_mutex'. However, hold 'reconfig_mutex' here is still problematic
    because this will cause deadlock, for example, commit 130443d60b1b ('md: refactor
    idle/frozen_sync_thread() to fix deadlock'). Fix this problem by using stop_sync_thread() to unregister
    sync_thread, like md/raid did.(CVE-2024-35808)

    In the Linux kernel, the following vulnerability has been resolved: of: dynamic: Synchronize
    of_changeset_destroy() with the devlink removals In the following sequence: 1) of_platform_depopulate() 2)
    of_overlay_remove() During the step 1, devices are destroyed and devlinks are removed. During the step 2,
    OF nodes are destroyed but __of_changeset_entry_destroy() can raise warnings related to missing
    of_node_put(): ERROR: memory leak, expected refcount 1 instead of 2 ... Indeed, during the devlink
    removals performed at step 1, the removal itself releasing the device (and the attached of_node) is done
    by a job queued in a workqueue and so, it is done asynchronously with respect to function calls. When the
    warning is present, of_node_put() will be called but wrongly too late from the workqueue job. In order to
    be sure that any ongoing devlink removals are done before the of_node destruction, synchronize the
    of_changeset_destroy() with the devlink removals.(CVE-2024-35879)

    In the Linux kernel, the following vulnerability has been resolved: nfs: Handle error of
    rpc_proc_register() in nfs_net_init(). syzkaller reported a warning [0] triggered while destroying
    immature netns. rpc_proc_register() was called in init_nfs_fs(), but its error has been ignored since at
    least the initial commit 1da177e4c3f4 ('Linux-2.6.12-rc2'). Recently, commit d47151b79e32 converted the
    procfs to per-netns and made the problem more visible. Even when rpc_proc_register() fails, nfs_net_init()
    could succeed, and thus nfs_net_exit() will be called while destroying the netns. Then,
    remove_proc_entry() will be called for non-existing proc directory and trigger the warning below. Let's
    handle the error of rpc_proc_register() properly in nfs_net_init().(CVE-2024-36939)

    In the Linux kernel, the following vulnerability has been resolved: PCI/PM: Drain runtime-idle callbacks
    before driver removal A race condition between the .runtime_idle() callback and the .remove() callback in
    the rtsx_pcr PCI driver leads to a kernel crash due to an unhandled page fault [1]. The problem is that
    rtsx_pci_runtime_idle() is not expected to be running after pm_runtime_get_sync() has been called, but the
    latter doesn't really guarantee that. It only guarantees that the suspend and resume callbacks will not be
    running when it returns. However, if a .runtime_idle() callback is already running when
    pm_runtime_get_sync() is called, the latter will notice that the runtime PM status of the device is
    RPM_ACTIVE and it will return right away without waiting for the former to complete. In fact, it cannot
    wait for .runtime_idle() to complete because it may be called from that callback (it arguably does not
    make much sense to do that, but it is not strictly prohibited). Thus in general, whoever is providing a
    .runtime_idle() callback needs to protect it from running in parallel with whatever code runs after
    pm_runtime_get_sync(). [Note that .runtime_idle() will not start after pm_runtime_get_sync() has returned,
    but it may continue running then if it has started earlier.] One way to address that race condition is to
    call pm_runtime_barrier() after pm_runtime_get_sync() (not before it, because a nonzero value of the
    runtime PM usage counter is necessary to prevent runtime PM callbacks from being invoked) to wait for the
    .runtime_idle() callback to complete should it be running at that point. A suitable place for doing that
    is in pci_device_remove() which calls pm_runtime_get_sync() before removing the driver, so it may as well
    call pm_runtime_barrier() subsequently, which will prevent the race in question from occurring, not just
    in the rtsx_pcr driver, but in any PCI drivers providing .runtime_idle() callbacks.(CVE-2024-35809)

    In the Linux kernel, the following vulnerability has been resolved: i40e: fix vf may be used uninitialized
    in this function warning To fix the regression introduced by commit 52424f974bc5, which causes servers
    hang in very hard to reproduce conditions with resets races. Using two sources for the information is the
    root cause. In this function before the fix bumping v didn't mean bumping vf pointer. But the code used
    this variables interchangeably, so stale vf could point to different/not intended vf. Remove redundant 'v'
    variable and iterate via single VF pointer across whole function instead to guarantee VF pointer
    validity.(CVE-2024-36020)

    In the Linux kernel, the following vulnerability has been resolved: clk: Fix clk_core_get NULL dereference
    It is possible for clk_core_get to dereference a NULL in the following sequence: clk_core_get()
    of_clk_get_hw_from_clkspec() __of_clk_get_hw_from_provider() __clk_get_hw() __clk_get_hw() can return NULL
    which is dereferenced by clk_core_get() at hw-core. Prior to commit dde4eff47c82 ('clk: Look for
    parents with clkdev based clk_lookups') the check IS_ERR_OR_NULL() was performed which would have caught
    the NULL. Reading the description of this function it talks about returning NULL but that cannot be so at
    the moment. Update the function to check for hw before dereferencing it and return NULL if hw is
    NULL.(CVE-2024-27038)

    In the Linux kernel, the following vulnerability has been resolved: dmaengine: idxd: Fix oops during rmmod
    on single-CPU platforms During the removal of the idxd driver, registered offline callback is invoked as
    part of the clean up process. However, on systems with only one CPU online, no valid target is available
    to migrate the perf context, resulting in a kernel oops: BUG: unable to handle page fault for address:
    000000000002a2b8.(CVE-2024-35989)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix unremoved procfs host
    directory regression Commit fc663711b944 ('scsi: core: Remove the /proc/scsi/${proc_name} directory
    earlier') fixed a bug related to modules loading/unloading, by adding a call to scsi_proc_hostdir_rm() on
    scsi_remove_host(). But that led to a potential duplicate call to the hostdir_rm() routine, since it's
    also called from scsi_host_dev_release(). That triggered a regression report, which was then fixed by
    commit be03df3d4bfe ('scsi: core: Fix a procfs host directory removal regression'). The fix just dropped
    the hostdir_rm() call from dev_release(). But it happens that this proc directory is created on
    scsi_host_alloc(), and that function 'pairs' with scsi_host_dev_release(), while scsi_remove_host() pairs
    with scsi_add_host(). In other words, it seems the reason for removing the proc directory on dev_release()
    was meant to cover cases in which a SCSI host structure was allocated, but the call to scsi_add_host()
    didn't happen. And that pattern happens to exist in some error paths, for example. Syzkaller causes that
    by using USB raw gadget device, error'ing on usb-storage driver, at usb_stor_probe2(). By checking that
    path, we can see that the BadDevice label leads to a scsi_host_put() after a SCSI host allocation, but
    there's no call to scsi_add_host() in such path. That leads to messages like this in dmesg (and a leak of
    the SCSI host proc structure): usb-storage 4-1:87.51: USB Mass Storage device detected proc_dir_entry
    'scsi/usb-storage' already registered WARNING: CPU: 1 PID: 3519 at fs/proc/generic.c:377
    proc_register+0x347/0x4e0 fs/proc/generic.c:376 The proper fix seems to still call scsi_proc_hostdir_rm()
    on dev_release(), but guard that with the state check for SHOST_CREATED; there is even a comment in
    scsi_host_dev_release() detailing that: such conditional is meant for cases where the SCSI host was
    allocated but there was no calls to {add,remove}_host(), like the usb-storage case. This is what we
    propose here and with that, the error path of usb-storage does not trigger the warning
    anymore.(CVE-2024-26935)

    In the Linux kernel, the following vulnerability has been resolved: scsi: bnx2fc: Remove spin_lock_bh
    while releasing resources after upload The session resources are used by FW and driver when session is
    offloaded, once session is uploaded these resources are not used. The lock is not required as these fields
    won't be used any longer. The offload and upload calls are sequential, hence lock is not
    required.(CVE-2024-36919)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix memory
    leak when canceling rehash work The rehash delayed work is rescheduled with a delay if the number of
    credits at end of the work is not negative as supposedly it means that the migration ended. Otherwise, it
    is rescheduled immediately. After 'mlxsw: spectrum_acl_tcam: Fix possible use-after-free during rehash'
    the above is no longer accurate as a non-negative number of credits is no longer indicative of the
    migration being done. It can also happen if the work encountered an error in which case the migration will
    resume the next time the work is scheduled. The significance of the above is that it is possible for the
    work to be pending and associated with hints that were allocated when the migration started. This leads to
    the hints being leaked [1] when the work is canceled while pending as part of ACL region dismantle. Fix by
    freeing the hints if hints are associated with a work that was canceled while pending. Blame the original
    commit since the reliance on not having a pending work associated with hints is fragile.(CVE-2024-35852)

    In the Linux kernel, the following vulnerability has been resolved: amd/amdkfd: sync all devices to wait
    all processes being evicted If there are more than one device doing reset in parallel, the first device
    will call kfd_suspend_all_processes() to evict all processes on all devices, this call takes time to
    finish. other device will start reset and recover without waiting. if the process has not been evicted
    before doing recover, it will be restored, then caused page fault.(CVE-2024-36949)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix possible
    use-after-free during rehash The rehash delayed work migrates filters from one region to another according
    to the number of available credits. The migrated from region is destroyed at the end of the work if the
    number of credits is non-negative as the assumption is that this is indicative of migration being
    complete. This assumption is incorrect as a non-negative number of credits can also be the result of a
    failed migration. The destruction of a region that still has filters referencing it can result in a use-
    after-free [1]. Fix by not destroying the region if migration failed.(CVE-2024-35854)

    In the Linux kernel, the following vulnerability has been resolved: net: hns3: fix kernel crash when
    devlink reload during pf initialization The devlink reload process will access the hardware resources, but
    the register operation is done before the hardware is initialized. So, processing the devlink reload
    during initialization may lead to kernel crash. This patch fixes this by taking devl_lock during
    initialization.(CVE-2024-36021)

    In the Linux kernel, the following vulnerability has been resolved: platform/x86: wmi: Fix opening of char
    device Since commit fa1f68db6ca7 ('drivers: misc: pass miscdevice pointer via file private data'), the
    miscdevice stores a pointer to itself inside filp-private_data, which means that private_data will not
    be NULL when wmi_char_open() is called. This might cause memory corruption should wmi_char_open() be
    unable to find its driver, something which can happen when the associated WMI device is deleted in
    wmi_free_devices(). Fix the problem by using the miscdevice pointer to retrieve the WMI device data
    associated with a char device using container_of(). This also avoids wmi_char_open() picking a wrong WMI
    device bound to a driver with the same name as the original driver.(CVE-2023-52864)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: discard table
    flag update with pending basechain deletion Hook unregistration is deferred to the commit phase, same
    occurs with hook updates triggered by the table dormant flag. When both commands are combined, this
    results in deleting a basechain while leaving its hook still registered in the core.(CVE-2024-35897)

    In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-v2: Check for non-
    NULL vCPU in vgic_v2_parse_attr() vgic_v2_parse_attr() is responsible for finding the vCPU that matches
    the user-provided CPUID, which (of course) may not be valid. If the ID is invalid, kvm_get_vcpu_by_id()
    returns NULL, which isn't handled gracefully. Similar to the GICv3 uaccess flow, check that
    kvm_get_vcpu_by_id() actually returns something and fail the ioctl if not.(CVE-2024-36953)

    In the Linux kernel, the following vulnerability has been resolved: net: fix __dst_negative_advice() race
    __dst_negative_advice() does not enforce proper RCU rules when sk-dst_cache must be cleared, leading to
    possible UAF. RCU rules are that we must first clear sk-sk_dst_cache, then call dst_release(old_dst).
    Note that sk_dst_reset(sk) is implementing this protocol correctly, while __dst_negative_advice() uses the
    wrong order. Given that ip6_negative_advice() has special logic against RTF_CACHE, this means each of the
    three -negative_advice() existing methods must perform the sk_dst_reset() themselves. Note the check
    against NULL dst is centralized in __dst_negative_advice(), there is no need to duplicate it in various
    callbacks. Many thanks to Clement Lecigne for tracking this issue. This old bug became visible after the
    blamed commit, using UDP sockets.(CVE-2024-36971)

    In the Linux kernel, the following vulnerability has been resolved: RDMA: Verify port when creating flow
    rule Validate port value provided by the user and with that remove no longer needed validation by the
    driver. The missing check in the mlx5_ib driver could cause to the below oops.(CVE-2021-47265)

    In the Linux kernel, the following vulnerability has been resolved: vt: fix unicode buffer corruption when
    deleting characters This is the same issue that was fixed for the VGA text buffer in commit 39cdb68c64d8
    ('vt: fix memory overlapping when deleting chars in the buffer'). The cure is also the same i.e. replace
    memcpy() with memmove() due to the overlaping buffers.(CVE-2024-35823)

    In the Linux kernel, the following vulnerability has been resolved: geneve: fix header validation in
    geneve[6]_xmit_skb syzbot is able to trigger an uninit-value in geneve_xmit() [1] Problem : While most ip
    tunnel helpers (like ip_tunnel_get_dsfield()) uses skb_protocol(skb, true), pskb_inet_may_pull() is only
    using skb-protocol. If anything else than ETH_P_IPV6 or ETH_P_IP is found in skb-protocol,
    pskb_inet_may_pull() does nothing at all. If a vlan tag was provided by the caller (af_packet in the
    syzbot case), the network header might not point to the correct location, and skb linear part could be
    smaller than expected. Add skb_vlan_inet_prepare() to perform a complete mac validation. Use this in
    geneve for the moment, I suspect we need to adopt this more broadly. v4 - Jakub reported v3 broke
    l2_tos_ttl_inherit.sh selftest - Only call __vlan_get_protocol() for vlan types.(CVE-2024-35973)

    In the Linux kernel, the following vulnerability has been resolved: i2c: smbus: fix NULL function pointer
    dereference Baruch reported an OOPS when using the designware controller as target only. Target-only modes
    break the assumption of one transfer function always being available. Fix this by always checking the
    pointer in __i2c_transfer. [wsa: dropped the simplification in core-smbus to avoid theoretical
    regressions](CVE-2024-35984)

    In the Linux kernel, the following vulnerability has been resolved: tipc: fix a possible memleak in
    tipc_buf_append __skb_linearize() doesn't free the skb when it fails, so move '*buf = NULL' after
    __skb_linearize(), so that the skb can be freed on the err path.(CVE-2024-36954)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: Fix infinite recursion in
    fib6_dump_done(). syzkaller reported infinite recursive calls of fib6_dump_done() during netlink socket
    destruction. [1] From the log, syzkaller sent an AF_UNSPEC RTM_GETROUTE message, and then the response was
    generated. The following recvmmsg() resumed the dump for IPv6, but the first call of inet6_dump_fib()
    failed at kzalloc() due to the fault injection.(CVE-2024-35886)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: reject new
    basechain after table flag update When dormant flag is toggled, hooks are disabled in the commit phase by
    iterating over current chains in table (existing and new). The following configuration allows for an
    inconsistent state: add table x add chain x y { type filter hook input priority 0; } add table x { flags
    dormant; } add chain x w { type filter hook input priority 1; } which triggers the following warning when
    trying to unregister chain w which is already unregistered.(CVE-2024-35900)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: do not compare
    internal table flags on updates Restore skipping transaction if table update does not modify
    flags.(CVE-2024-27065)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: bridge: confirm multicast
    packets before passing them up the stack conntrack nf_confirm logic cannot handle cloned skbs referencing
    the same nf_conn entry, which will happen for multicast (broadcast) frames on bridges. Example: macvlan0 |
    br0 / \ ethX ethY ethX (or Y) receives a L2 multicast or broadcast packet containing an IP packet, flow is
    not yet in conntrack table. 1. skb passes through bridge and fake-ip (br_netfilter)Prerouting. - skb-
    _nfct now references a unconfirmed entry 2. skb is broad/mcast packet. bridge now passes clones out on
    each bridge interface. 3. skb gets passed up the stack. 4. In macvlan case, macvlan driver retains
    clone(s) of the mcast skb and schedules a work queue to send them out on the lower devices. The clone skb-
    _nfct is not a copy, it is the same entry as the original skb. The macvlan rx handler then returns
    RX_HANDLER_PASS. 5. Normal conntrack hooks (in NF_INET_LOCAL_IN) confirm the orig skb. The Macvlan
    broadcast worker and normal confirm path will race. This race will not happen if step 2 already confirmed
    a clone. In that case later steps perform skb_clone() with skb-_nfct already confirmed (in hash table).
    This works fine. But such confirmation won't happen when eb/ip/nftables rules dropped the packets before
    they reached the nf_confirm step in postrouting. Pablo points out that nf_conntrack_bridge doesn't allow
    use of stateful nat, so we can safely discard the nf_conn entry and let inet call conntrack again. This
    doesn't work for bridge netfilter: skb could have a nat transformation. Also bridge nf prevents re-
    invocation of inet prerouting via 'sabotage_in' hook. Work around this problem by explicit confirmation of
    the entry at LOCAL_IN time, before upper layer has a chance to clone the unconfirmed entry. The downside
    is that this disables NAT and conntrack helpers. Alternative fix would be to add locking to all code parts
    that deal with unconfirmed packets, but even if that could be done in a sane way this opens up other
    problems, for example: -m physdev --physdev-out eth0 -j SNAT --snat-to 1.2.3.4 -m physdev --physdev-out
    eth1 -j SNAT --snat-to 1.2.3.5 For multicast case, only one of such conflicting mappings will be created,
    conntrack only handles 1:1 NAT mappings. Users should set create a setup that explicitly marks such
    traffic NOTRACK (conntrack bypass) to avoid this, but we cannot auto-bypass them, ruleset might have
    accept rules for untracked traffic already, so user-visible behaviour would change.(CVE-2024-27415)

    In the Linux kernel, the following vulnerability has been resolved: net: esp: fix bad handling of pages
    from page_pool When the skb is reorganized during esp_output (!esp-inline), the pages coming from the
    original skb fragments are supposed to be released back to the system through put_page. But if the skb
    fragment pages are originating from a page_pool, calling put_page on them will trigger a page_pool leak
    which will eventually result in a crash.(CVE-2024-26953)

    In the Linux kernel, the following vulnerability has been resolved: firewire: ohci: mask bus reset
    interrupts between ISR and bottom half In the FireWire OHCI interrupt handler, if a bus reset interrupt
    has occurred, mask bus reset interrupts until bus_reset_work has serviced and cleared the interrupt.
    Normally, we always leave bus reset interrupts masked. We infer the bus reset from the self-ID interrupt
    that happens shortly thereafter. A scenario where we unmask bus reset interrupts was introduced in 2008 in
    a007bb857e0b26f5d8b73c2ff90782d9c0972620: If OHCI_PARAM_DEBUG_BUSRESETS (8) is set in the debug parameter
    bitmask, we will unmask bus reset interrupts so we can log them. irq_handler logs the bus reset interrupt.
    However, we can't clear the bus reset event flag in irq_handler, because we won't service the event until
    later. irq_handler exits with the event flag still set. If the corresponding interrupt is still unmasked,
    the first bus reset will usually freeze the system due to irq_handler being called again each time it
    exits. This freeze can be reproduced by loading firewire_ohci with 'modprobe firewire_ohci debug=-1' (to
    enable all debugging output). Apparently there are also some cases where bus_reset_work will get called
    soon enough to clear the event, and operation will continue normally. This freeze was first reported a few
    months after a007bb85 was committed, but until now it was never fixed. The debug level could safely be set
    to -1 through sysfs after the module was loaded, but this would be ineffectual in logging bus reset
    interrupts since they were only unmasked during initialization. irq_handler will now leave the event flag
    set but mask bus reset interrupts, so irq_handler won't be called again and there will be no freeze. If
    OHCI_PARAM_DEBUG_BUSRESETS is enabled, bus_reset_work will unmask the interrupt after servicing the event,
    so future interrupts will be caught as desired. As a side effect to this change,
    OHCI_PARAM_DEBUG_BUSRESETS can now be enabled through sysfs in addition to during initial module loading.
    However, when enabled through sysfs, logging of bus reset interrupts will be effective only starting with
    the second bus reset, after bus_reset_work has executed.(CVE-2024-36950)

    In the Linux kernel, the following vulnerability has been resolved: net: fix out-of-bounds access in
    ops_init net_alloc_generic is called by net_alloc, which is called without any locking. It reads
    max_gen_ptrs, which is changed under pernet_ops_rwsem. It is read twice, first to allocate an array, then
    to set s.len, which is later used to limit the bounds of the array access. It is possible that the array
    is allocated and another thread is registering a new pernet ops, increments max_gen_ptrs, which is then
    used to set s.len with a larger than allocated length for the variable array. Fix it by reading
    max_gen_ptrs only once in net_alloc_generic. If max_gen_ptrs is later incremented, it will be caught in
    net_assign_generic.(CVE-2024-36883)

    In the Linux kernel, the following vulnerability has been resolved: tcp: defer shutdown(SEND_SHUTDOWN) for
    TCP_SYN_RECV sockets TCP_SYN_RECV state is really special, it is only used by cross-syn connections,
    mostly used by fuzzers. In the following crash [1], syzbot managed to trigger a divide by zero in
    tcp_rcv_space_adjust() A socket makes the following state transitions, without ever calling
    tcp_init_transfer(), meaning tcp_init_buffer_space() is also not called. TCP_CLOSE connect() TCP_SYN_SENT
    TCP_SYN_RECV shutdown() - tcp_shutdown(sk, SEND_SHUTDOWN) TCP_FIN_WAIT1 To fix this issue, change
    tcp_shutdown() to not perform a TCP_SYN_RECV - TCP_FIN_WAIT1 transition, which makes no sense anyway.
    When tcp_rcv_state_process() later changes socket state from TCP_SYN_RECV to TCP_ESTABLISH, then look at
    sk-sk_shutdown to finally enter TCP_FIN_WAIT1 state, and send a FIN packet from a sane socket state.
    This means tcp_send_fin() can now be called from BH context, and must use GFP_ATOMIC
    allocations.(CVE-2024-36905)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: use timestamp to
    check for set element timeout Add a timestamp field at the beginning of the transaction, store it in the
    nftables per-netns area. Update set backend .insert, .deactivate and sync gc path to use the timestamp,
    this avoids that an element expires while control plane transaction is still unfinished. .lookup and
    .update, which are used from packet path, still use the current time to check if the element has expired.
    And .get path and dump also since this runs lockless under rcu read size lock. Then, there is async gc
    which also needs to check the current time since it runs asynchronously from a workqueue.(CVE-2024-27397)

    In the Linux kernel, the following vulnerability has been resolved: bpf, skmsg: Fix NULL pointer
    dereference in sk_psock_skb_ingress_enqueue Fix NULL pointer data-races in sk_psock_skb_ingress_enqueue()
    which syzbot reported [1].(CVE-2024-36938)

    In the Linux kernel, the following vulnerability has been resolved: tty: n_gsm: fix possible out-of-bounds
    in gsm0_receive() Assuming the following: - side A configures the n_gsm in basic option mode - side B
    sends the header of a basic option mode frame with data length 1 - side A switches to advanced option mode
    - side B sends 2 data bytes which exceeds gsm-len Reason: gsm-len is not used in advanced option
    mode. - side A switches to basic option mode - side B keeps sending until gsm0_receive() writes past gsm-
    buf Reason: Neither gsm-state nor gsm-len have been reset after reconfiguration. Fix this by
    changing gsm-count to gsm-len comparison from equal to less than. Also add upper limit checks
    against the constant MAX_MRU in gsm0_receive() and gsm1_receive() to harden against memory corruption of
    gsm-len and gsm-mru. All other checks remain as we still need to limit the data according to the
    user configuration and actual payload size.(CVE-2024-36016)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: fib6_rules: avoid possible NULL
    dereference in fib6_rule_action() syzbot is able to trigger the following crash [1], caused by unsafe
    ip6_dst_idev() use. Indeed ip6_dst_idev() can return NULL, and must always be checked.(CVE-2024-36902)

    In the Linux kernel, the following vulnerability has been resolved: ipvlan: add ipvlan_route_v6_outbound()
    helper Inspired by syzbot reports using a stack of multiple ipvlan devices. Reduce stack size needed in
    ipvlan_process_v6_outbound() by moving the flowi6 struct used for the route lookup in an non inlined
    helper. ipvlan_route_v6_outbound() needs 120 bytes on the stack, immediately reclaimed. Also make sure
    ipvlan_process_v4_outbound() is not inlined. We might also have to lower MAX_NEST_DEV, because only syzbot
    uses setups with more than four stacked devices.(CVE-2023-52796)

    In the Linux kernel, the following vulnerability has been resolved: i40e: Do not use WQ_MEM_RECLAIM flag
    for workqueue Issue reported by customer during SRIOV testing, call trace: When both i40e and the i40iw
    driver are loaded, a warning in check_flush_dependency is being triggered. This seems to be because of the
    i40e driver workqueue is allocated with the WQ_MEM_RECLAIM flag, and the i40iw one is not. Similar error
    was encountered on ice too and it was fixed by removing the flag. Do the same for i40e
    too.(CVE-2024-36004)

    In the Linux kernel, the following vulnerability has been resolved: HID: i2c-hid: remove
    I2C_HID_READ_PENDING flag to prevent lock-up The flag I2C_HID_READ_PENDING is used to serialize I2C
    operations. However, this is not necessary, because I2C core already has its own locking for that. More
    importantly, this flag can cause a lock-up: if the flag is set in i2c_hid_xfer() and an interrupt happens,
    the interrupt handler (i2c_hid_irq) will check this flag and return immediately without doing anything,
    then the interrupt handler will be invoked again in an infinite loop. Since interrupt handler is an RT
    task, it takes over the CPU and the flag-clearing task never gets scheduled, thus we have a lock-up.
    Delete this unnecessary flag.(CVE-2024-35997)

    In the Linux kernel, the following vulnerability has been resolved: bpf, sockmap: Prevent lock inversion
    deadlock in map delete elem syzkaller started using corpuses where a BPF tracing program deletes elements
    from a sockmap/sockhash map. Because BPF tracing programs can be invoked from any interrupt context, locks
    taken during a map_delete_elem operation must be hardirq-safe. Otherwise a deadlock due to lock inversion
    is possible, as reported by lockdep: CPU0 CPU1 ---- ---- lock(htab-buckets[i].lock);
    local_irq_disable(); lock(host-lock); lock(htab-buckets[i].lock); Interrupt
    lock(host-lock); Locks in sockmap are hardirq-unsafe by design. We expects elements to be deleted
    from sockmap/sockhash only in task (normal) context with interrupts enabled, or in softirq context. Detect
    when map_delete_elem operation is invoked from a context which is _not_ hardirq-unsafe, that is interrupts
    are disabled, and bail out with an error. Note that map updates are not affected by this issue. BPF
    verifier does not allow updating sockmap/sockhash from a BPF tracing program today.(CVE-2024-35895)

    In the Linux kernel, the following vulnerability has been resolved: scsi: iscsi: Fix iscsi_task use after
    free Commit d39df158518c ('scsi: iscsi: Have abort handler get ref to conn') added
    iscsi_get_conn()/iscsi_put_conn() calls during abort handling but then also changed the handling of the
    case where we detect an already completed task where we now end up doing a goto to the common put/cleanup
    code. This results in a iscsi_task use after free, because the common cleanup code will do a put on the
    iscsi_task. This reverts the goto and moves the iscsi_get_conn() to after we've checked if the iscsi_task
    is valid.(CVE-2021-47427)

    In the Linux kernel, the following vulnerability has been resolved: tcp: TX zerocopy should not sense
    pfmemalloc status We got a recent syzbot report [1] showing a possible misuse of pfmemalloc page status in
    TCP zerocopy paths. Indeed, for pages coming from user space or other layers, using page_is_pfmemalloc()
    is moot, and possibly could give false positives. There has been attempts to make page_is_pfmemalloc()
    more robust, but not using it in the first place in this context is probably better, removing cpu cycles.
    Note to stable teams : You need to backport 84ce071e38a6 ('net: introduce __skb_fill_page_desc_noacc') as
    a prereq. Race is more probable after commit c07aea3ef4d4 ('mm: add a signature in struct page') because
    page_is_pfmemalloc() is now using low order bit from page-lru.next, which can change more often than
    page-index. Low order bit should never be set for lru.next (when used as an anchor in LRU list), so
    KCSAN report is mostly a false positive. Backporting to older kernel versions seems not
    necessary.(CVE-2022-48689)

    In the Linux kernel, the following vulnerability has been resolved: pinctrl: devicetree: fix refcount leak
    in pinctrl_dt_to_map() If we fail to allocate propname buffer, we need to drop the reference count we just
    took. Because the pinctrl_dt_free_maps() includes the droping operation, here we call it
    directly.(CVE-2024-36959)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: CPPC: Use access_width over
    bit_width for system memory accesses To align with ACPI 6.3+, since bit_width can be any 8-bit value, it
    cannot be depended on to be always on a clean 8b boundary. This was uncovered on the Cobalt 100
    platform.(CVE-2024-35995)

    In the Linux kernel, the following vulnerability has been resolved: clk: Get runtime PM before walking
    tree during disable_unused Doug reported [1] the following hung task: INFO: task swapper/0:1 blocked for
    more than 122 seconds. Not tainted 5.15.149-21875-gf795ebc40eb8 #1 'echo 0 
    /proc/sys/kernel/hung_task_timeout_secs' disables this message.(CVE-2024-27004)

    In the Linux kernel, the following vulnerability has been resolved: Bluetooth: L2CAP: Fix div-by-zero in
    l2cap_le_flowctl_init() l2cap_le_flowctl_init() can cause both div-by-zero and an integer overflow since
    hdev-le_mtu may not fall in the valid range. Move MTU from hci_dev to hci_conn to validate MTU and stop
    the connection process earlier if MTU is invalid. Also, add a missing validation in read_buffer_size() and
    make it return an error value if the validation fails.(CVE-2024-36968)

    In the Linux kernel, the following vulnerability has been resolved: net: sched: sch_multiq: fix possible
    OOB write in multiq_tune() q-bands will be assigned to qopt-bands to execute subsequent code logic
    after kmalloc. So the old q-bands should not be used in kmalloc. Otherwise, an out-of-bounds write will
    occur.(CVE-2024-36978)

    In the Linux kernel, the following vulnerability has been resolved: ring-buffer: Fix a race between
    readers and resize checks The reader code in rb_get_reader_page() swaps a new reader page into the ring
    buffer by doing cmpxchg on old-list.prev-next to point it to the new page. Following that, if the
    operation is successful, old-list.next-prev gets updated too. This means the underlying doubly-
    linked list is temporarily inconsistent, page-prev-next or page-next-prev might not be equal
    back to page for some page in the ring buffer. The resize operation in ring_buffer_resize() can be invoked
    in parallel.(CVE-2024-38601)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: validate user input for
    expected length I got multiple syzbot reports showing old bugs exposed by BPF after commit 20f2505fb436
    ('bpf: Try to avoid kzalloc in cgroup/{s,g}etsockopt') setsockopt() @optlen argument should be taken into
    account before copying data.(CVE-2024-35896)

    In the Linux kernel, the following vulnerability has been resolved: tipc: fix UAF in error path Sam Page
    (sam4k) working with Trend Micro Zero Day Initiative reported a UAF in the tipc_buf_append() error path:
    BUG: KASAN: slab-use-after-free in kfree_skb_list_reason+0x47e/0x4c0 linux/net/core/skbuff.c:1183 Read of
    size 8 at addr ffff88804d2a7c80 by task poc/8034.(CVE-2024-36886)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: restore set
    elements when delete set fails From abort path, nft_mapelem_activate() needs to restore refcounters to the
    original state. Currently, it uses the set-ops-walk() to iterate over these set elements. The
    existing set iterator skips inactive elements in the next generation, this does not work from the abort
    path to restore the original state since it has to skip active elements instead (not inactive ones). This
    patch moves the check for inactive elements to the set iterator callback, then it reverses the logic for
    the .activate case which needs to skip active elements. Toggle next generation bit for elements when
    delete set command is invoked and call nft_clear() from .activate (abort) path to restore the next
    generation bit.(CVE-2024-27012)

    In the Linux kernel, the following vulnerability has been resolved: net: hns3: fix kernel crash when
    devlink reload during initialization The devlink reload process will access the hardware resources, but
    the register operation is done before the hardware is initialized. So, processing the devlink reload
    during initialization may lead to kernel crash. This patch fixes this by registering the devlink after
    hardware initialization.(CVE-2024-36900)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Skip on writeback
    when it's not applicable [WHY] dynamic memory safety error detector (KASAN) catches and generates error
    messages 'BUG: KASAN: slab-out-of-bounds' as writeback connector does not support certain features which
    are not initialized. [HOW] Skip them when connector type is DRM_MODE_CONNECTOR_WRITEBACK.(CVE-2024-36914)

    In the Linux kernel, the following vulnerability has been resolved: spi: Fix deadlock when adding SPI
    controllers on SPI buses Currently we have a global spi_add_lock which we take when adding new devices so
    that we can check that we're not trying to reuse a chip select that's already controlled. This means that
    if the SPI device is itself a SPI controller and triggers the instantiation of further SPI devices we
    trigger a deadlock as we try to register and instantiate those devices while in the process of doing so
    for the parent controller and hence already holding the global spi_add_lock. Since we only care about
    concurrency within a single SPI bus move the lock to be per controller, avoiding the deadlock. This can be
    easily triggered in the case of spi-mux.(CVE-2021-47469)

    In the Linux kernel, the following vulnerability has been resolved: nsh: Restore skb-
    {protocol,data,mac_header} for outer header in nsh_gso_segment(). syzbot triggered various splats (see
    [0] and links) by a crafted GSO packet of VIRTIO_NET_HDR_GSO_UDP layering the following protocols:
    ETH_P_8021AD + ETH_P_NSH + ETH_P_IPV6 + IPPROTO_UDP NSH can encapsulate IPv4, IPv6, Ethernet, NSH, and
    MPLS. As the inner protocol can be Ethernet, NSH GSO handler, nsh_gso_segment(), calls
    skb_mac_gso_segment() to invoke inner protocol GSO handlers. nsh_gso_segment() does the following for the
    original skb before calling skb_mac_gso_segment() 1. reset skb-network_header 2. save the original skb-
    {mac_heaeder,mac_len} in a local variable 3. pull the NSH header 4. resets skb-mac_header 5. set up
    skb-mac_len and skb-protocol for the inner protocol. and does the following for the segmented skb 6.
    set ntohs(ETH_P_NSH) to skb-protocol 7. push the NSH header 8. restore skb-mac_header 9. set skb-
    mac_header + mac_len to skb-network_header 10. restore skb-mac_len There are two problems in 6-7
    and 8-9. (a) After 6  7, skb-data points to the NSH header, so the outer header (ETH_P_8021AD in
    this case) is stripped when skb is sent out of netdev. Also, if NSH is encapsulated by NSH + Ethernet (so
    NSH-Ethernet-NSH), skb_pull() in the first nsh_gso_segment() will make skb-data point to the middle of
    the outer NSH or Ethernet header because the Ethernet header is not pulled by the second
    nsh_gso_segment(). (b) While restoring skb-{mac_header,network_header} in 8  9, nsh_gso_segment()
    does not assume that the data in the linear buffer is shifted. However, udp6_ufo_fragment() could shift
    the data and change skb-mac_header accordingly as demonstrated by syzbot. If this happens, even the
    restored skb-mac_header points to the middle of the outer header. It seems nsh_gso_segment() has never
    worked with outer headers so far. At the end of nsh_gso_segment(), the outer header must be restored for
    the segmented skb, instead of the NSH header. To do that, let's calculate the outer header position
    relatively from the inner header and set skb-{data,mac_header,protocol} properly.(CVE-2024-36933)

    In the Linux kernel, the following vulnerability has been resolved: ipv4: Fix uninit-value access in
    __ip_make_skb() KMSAN reported uninit-value access in __ip_make_skb() [1]. __ip_make_skb() tests HDRINCL
    to know if the skb has icmphdr. However, HDRINCL can cause a race condition. If calling setsockopt(2) with
    IP_HDRINCL changes HDRINCL while __ip_make_skb() is running, the function will access icmphdr in the skb
    even if it is not included. This causes the issue reported by KMSAN. Check FLOWI_FLAG_KNOWN_NH on
    fl4-flowi4_flags instead of testing HDRINCL on the socket. Also, fl4-fl4_icmp_type and
    fl4-fl4_icmp_code are not initialized. These are union in struct flowi4 and are implicitly initialized
    by flowi4_init_output(), but we should not rely on specific union layout. Initialize these explicitly in
    raw_sendmsg().(CVE-2024-36927)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_pipapo: walk over
    current view on netlink dump The generation mask can be updated while netlink dump is in progress. The
    pipapo set backend walk iterator cannot rely on it to infer what view of the datastructure is to be used.
    Add notation to specify if user wants to read/update the set. Based on patch from Florian
    Westphal.(CVE-2024-27017)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Add BPF_PROG_TYPE_CGROUP_SKB
    attach type enforcement in BPF_LINK_CREATE bpf_prog_attach uses attach_type_to_prog_type to enforce proper
    attach type for BPF_PROG_TYPE_CGROUP_SKB. link_create uses bpf_prog_get and relies on
    bpf_prog_attach_check_attach_type to properly verify prog_type  attach_type association. Add missing
    attach_type enforcement for the link_create case. Otherwise, it's currently possible to attach cgroup_skb
    prog types to other cgroup hooks.(CVE-2024-38564)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Allow delete from
    sockmap/sockhash only if update is allowed We have seen an influx of syzkaller reports where a BPF program
    attached to a tracepoint triggers a locking rule violation by performing a map_delete on a
    sockmap/sockhash. We don't intend to support this artificial use scenario. Extend the existing verifier
    allowed-program-type check for updating sockmap/sockhash to also cover deleting from a map. From now on
    only BPF programs which were previously allowed to update sockmap/sockhash can delete from these map
    types.(CVE-2024-38662)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix possible
    use-after-free during activity update The rule activity update delayed work periodically traverses the
    list of configured rules and queries their activity from the device. As part of this task it accesses the
    entry pointed by 'ventry-entry', but this entry can be changed concurrently by the rehash delayed work,
    leading to a use-after-free [1]. Fix by closing the race and perform the activity query under the
    'vregion-lock' mutex.(CVE-2024-35855)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2206
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edb39fd9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h1479.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1479.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1479.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1479.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1479.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1479.eulerosv2r11"
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
