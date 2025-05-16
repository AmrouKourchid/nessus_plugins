#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206930);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2021-47473",
    "CVE-2022-48666",
    "CVE-2022-48689",
    "CVE-2022-48691",
    "CVE-2022-48703",
    "CVE-2023-28746",
    "CVE-2023-52652",
    "CVE-2023-52656",
    "CVE-2023-52676",
    "CVE-2023-52683",
    "CVE-2023-52686",
    "CVE-2023-52698",
    "CVE-2024-26646",
    "CVE-2024-26828",
    "CVE-2024-26830",
    "CVE-2024-26845",
    "CVE-2024-26857",
    "CVE-2024-26907",
    "CVE-2024-26923",
    "CVE-2024-26924",
    "CVE-2024-26925",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26947",
    "CVE-2024-26958",
    "CVE-2024-26960",
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
    "CVE-2024-27019",
    "CVE-2024-27038",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27046",
    "CVE-2024-27059",
    "CVE-2024-27073",
    "CVE-2024-27075",
    "CVE-2024-27389",
    "CVE-2024-27395",
    "CVE-2024-27431",
    "CVE-2024-35791",
    "CVE-2024-35807",
    "CVE-2024-35835",
    "CVE-2024-35847",
    "CVE-2024-36006",
    "CVE-2024-36008"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-2352)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix a memory leak in an
    error path of qla2x00_process_els() Commit 8c0eb596baa5 ('[SCSI] qla2xxx: Fix a memory leak in an error
    path of qla2x00_process_els()'), intended to change: bsg_job-request-msgcode ==
    FC_BSG_HST_ELS_NOLOGIN bsg_job-request-msgcode != FC_BSG_RPT_ELS but changed it to: bsg_job-
    request-msgcode == FC_BSG_RPT_ELS instead. Change the == to a != to avoid leaking the fcport
    structure or freeing unallocated memory.(CVE-2021-47473)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: LPIT: Avoid u32 multiplication
    overflow In lpit_update_residency() there is a possibility of overflow in multiplication, if tsc_khz is
    large enough ( UINT_MAX/1000). Change multiplication to mul_u32_u32(). Found by Linux Verification
    Center (linuxtesting.org) with SVACE.(CVE-2023-52683)

    In the Linux kernel, the following vulnerability has been resolved: ipv4: check for NULL idev in
    ip_route_use_hint() syzbot was able to trigger a NULL deref in fib_validate_source() in an old tree [1].
    It appears the bug exists in latest trees. All calls to __in_dev_get_rcu() must be checked for a NULL
    result. [1] general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] SMP
    KASAN KASAN: null-ptr-deref in range[0x0000000000000000-0x0000000000000007(CVE-2024-36008)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: clean up hook
    list when offload flags check fails splice back the hook list so nft_chain_release_hook() has a chance to
    release the hooks.(CVE-2022-48691)

    In the Linux kernel, the following vulnerability has been resolved: calipso: fix memory leak in
    netlbl_calipso_add_pass() If IPv6 support is disabled at boot (ipv6.disable=1), the calipso_init() -
    netlbl_calipso_ops_register() function isn't called, and the netlbl_calipso_ops_get() function always
    returns NULL. In this case, the netlbl_calipso_add_pass() function allocates memory for the doi_def
    variable but doesn't free it with the calipso_doi_free().(CVE-2023-52698)

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

    In the Linux kernel, the following vulnerability has been resolved: bpf: Guard stack limits against 32bit
    overflow This patch promotes the arithmetic around checking stack bounds to be done in the 64-bit domain,
    instead of the current 32bit. The arithmetic implies adding together a 64-bit register with a int offset.
    The register was checked to be below 129 when it was variable, but not when it was fixed. The offset
    either comes from an instruction (in which case it is 16 bit), from another register (in which case the
    caller checked it to be below 129 [1]), or from the size of an argument to a kfunc (in which case it
    can be a u32 [2]). Between the register being inconsistently checked to be below 129, and the offset
    being up to an u32, it appears that we were open to overflowing the `int`s which were currently used for
    arithmetic.(CVE-2023-52676)

    In the Linux kernel, the following vulnerability has been resolved: powerpc/powernv: Add a null pointer
    check in opal_event_init() kasprintf() returns a pointer to dynamically allocated memory which can be NULL
    upon failure.(CVE-2023-52686)

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

    In the Linux kernel, the following vulnerability has been resolved:net: openvswitch: Fix Use-After-Free in
    ovs_ct_exit.Since kfree_rcu, which is called in the hlist_for_each_entry_rcu traversal of
    ovs_ct_limit_exit, is not part of the RCU read critical section, it is possible that the RCU grace period
    will pass during the traversal and the key will be free.To prevent this, it should be changed to
    hlist_for_each_entry_safe.(CVE-2024-27395)

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

    In the Linux kernel, the following vulnerability has been resolved: nfp: flower: handle acti_netdevs
    allocation failure The kmalloc_array() in nfp_fl_lag_do_work() will return null, if the physical memory
    has run out. As a result, if we dereference the acti_netdevs, the null pointer dereference bugs will
    happen. This patch adds a check to judge whether allocation failure occurs. If it happens, the delayed
    work will be rescheduled and try again.(CVE-2024-27046)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: Fix potential
    data-race in __nft_obj_type_get() nft_unregister_obj() can concurrent with __nft_obj_type_get(), and there
    is not any protection when iterate over nf_tables_objects list in __nft_obj_type_get(). Therefore, there
    is potential data-race of nf_tables_objects list entry. Use list_for_each_entry_rcu() to iterate over
    nf_tables_objects list in __nft_obj_type_get(), and use rcu_read_lock() in the caller nft_obj_type_get()
    to protect the entire type query process.(CVE-2024-27019)

    In the Linux kernel, the following vulnerability has been resolved: clk: Get runtime PM before walking
    tree during disable_unused Doug reported [1] the following hung task: INFO: task swapper/0:1 blocked for
    more than 122 seconds. Not tainted 5.15.149-21875-gf795ebc40eb8 #1 'echo 0 
    /proc/sys/kernel/hung_task_timeout_secs' disables this message.(CVE-2024-27004)

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

    In the Linux kernel, the following vulnerability has been resolved: NTB: fix possible name leak in
    ntb_register_device() If device_register() fails in ntb_register_device(), the device name allocated by
    dev_set_name() should be freed. As per the comment in device_register(), callers should use put_device()
    to give up the reference in the error path. So fix this by calling put_device() in the error path so that
    the name can be freed in kobject_cleanup(). As a result of this, put_device() in the error path of
    ntb_register_device() is removed and the actual error is returned.(CVE-2023-52652)

    In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix command flush on
    cable pull System crash due to command failed to flush back to SCSI layer. BUG: unable to handle kernel
    NULL pointer dereference at 0000000000000000 PGD 0 P4D 0 Oops: 0000(CVE-2024-26931)

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

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: restore set
    elements when delete set fails From abort path, nft_mapelem_activate() needs to restore refcounters to the
    original state. Currently, it uses the set-ops-walk() to iterate over these set elements. The
    existing set iterator skips inactive elements in the next generation, this does not work from the abort
    path to restore the original state since it has to skip active elements instead (not inactive ones). This
    patch moves the check for inactive elements to the set iterator callback, then it reverses the logic for
    the .activate case which needs to skip active elements. Toggle next generation bit for elements when
    delete set command is invoked and call nft_clear() from .activate (abort) path to restore the next
    generation bit.(CVE-2024-27012)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Prevent deadlock while
    disabling aRFS When disabling aRFS under the `priv-state_lock`, any scheduled aRFS works are canceled
    using the `cancel_work_sync` function, which waits for the work to end if it has already started. However,
    while waiting for the work handler, the handler will try to acquire the `state_lock` which is already
    acquired. The worker acquires the lock to delete the rules if the state is down, which is not the worker's
    responsibility since disabling aRFS deletes the rules. Add an aRFS state variable, which indicates whether
    the aRFS is enabled and prevent adding rules when the aRFS is disabled.(CVE-2024-27014)

    In the Linux kernel, the following vulnerability has been resolved: tun: limit printing rate when illegal
    packet received by tun dev vhost_worker will call tun call backs to receive packets. If too many illegal
    packets arrives, tun_do_read will keep dumping packet contents. When console is enabled, it will costs
    much more cpu time to dump packet and soft lockup will be detected. net_ratelimit mechanism can be used to
    limit the dumping rate.(CVE-2024-27013)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix memleak in
    map from abort path The delete set command does not rely on the transaction object for element removal,
    therefore, a combination of delete element + delete set from the abort path could result in restoring
    twice the refcount of the mapping. Check for inactive element in the next generation for the delete
    element command in the abort path, skip restoring state if next generation bit has been already cleared.
    This is similar to the activate logic using the set walk iterator.(CVE-2024-27011)

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27073)

    In the Linux kernel, the following vulnerability has been resolved: drm: nv04: Fix out of bounds access
    When Output Resource (dcb-or) value is assigned in fabricate_dcb_output(), there may be out of bounds
    access to dac_users array in case dcb-or is zero because ffs(dcb-or) is used as index there. The
    'or' argument of fabricate_dcb_output() must be interpreted as a number of bit to set, not value. Utilize
    macros from 'enum nouveau_or' in calls instead of hardcoding. Found by Linux Verification Center
    (linuxtesting.org) with SVACE.(CVE-2024-27008)

    In the Linux kernel, the following vulnerability has been resolved: crypto: qat - resolve race condition
    during AER recovery During the PCI AER system's error recovery process, the kernel driver may encounter a
    race condition with freeing the reset_data structure's memory. If the device restart will take more than
    10 seconds the function scheduling that restart will exit due to a timeout, and the reset_data structure
    will be freed. However, this data structure is used for completion notification after the restart is
    completed, which leads to a UAF bug.(CVE-2024-26974)

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

    In the Linux kernel, the following vulnerability has been resolved: media: edia: dvbdev: fix a use-after-
    free In dvb_register_device, *pdvbdev is set equal to dvbdev, which is freed in several error-handling
    paths. However, *pdvbdev is not set to NULL after dvbdev's deallocation, causing use-after-frees in many
    places, for example, in the following call chain: budget_register |- dvb_dmxdev_init |-
    dvb_register_device |- dvb_dmxdev_release |- dvb_unregister_device |- dvb_remove_device |-
    dvb_device_put |- kref_put When calling dvb_unregister_device, dmxdev-dvbdev (i.e. *pdvbdev in
    dvb_register_device) could point to memory that had been freed in dvb_register_device. Thereafter, this
    pointer is transferred to kref_put and triggering a use-after-free.(CVE-2024-27043)

    In the Linux kernel, the following vulnerability has been resolved: USB: usb-storage: Prevent divide-by-0
    error in isd200_ata_command The isd200 sub-driver in usb-storage uses the HEADS and SECTORS values in the
    ATA ID information to calculate cylinder and head values when creating a CDB for READ or WRITE commands.
    The calculation involves division and modulus operations, which will cause a crash if either of these
    values is 0. While this never happens with a genuine device, it could happen with a flawed or subversive
    emulation, as reported by the syzbot fuzzer. Protect against this possibility by refusing to bind to the
    device if either the ATA_ID_HEADS or ATA_ID_SECTORS value in the device's ID information is 0. This
    requires isd200_Initialization() to return a negative error code when initialization fails; currently it
    always returns 0 (even when there is an error).(CVE-2024-27059)

    In the Linux kernel, the following vulnerability has been resolved: thermal/int340x_thermal: handle
    data_vault when the value is ZERO_SIZE_PTR In some case, the GDDV returns a package with a buffer which
    has zero length. It causes that kmemdup() returns ZERO_SIZE_PTR (0x10). Then the data_vault_read() got
    NULL point dereference problem when accessing the 0x10 value in data_vault. [ 71.024560] BUG: kernel NULL
    pointer dereference, address: 0000000000000010 This patch uses ZERO_OR_NULL_PTR() for checking
    ZERO_SIZE_PTR or NULL value in data_vault.(CVE-2022-48703)

    In the Linux kernel, the following vulnerability has been resolved: nfs: fix UAF in direct writes In
    production we have been hitting the following warning consistently(CVE-2024-26958)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: Fix mirred deadlock on
    device recursion When the mirred action is used on a classful egress qdisc and a packet is mirrored or
    redirected to self we hit a qdisc lock deadlock.(CVE-2024-27010)

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

    In the Linux kernel, the following vulnerability has been resolved: init/main.c: Fix potential
    static_command_line memory overflow We allocate memory of size 'xlen + strlen(boot_command_line) + 1' for
    static_command_line, but the strings copied into static_command_line are extra_command_line and
    command_line, rather than extra_command_line and boot_command_line. When strlen(command_line) 
    strlen(boot_command_line), static_command_line will overflow. This patch just recovers
    strlen(command_line) which was miss-consolidated with strlen(boot_command_line) in the commit f5c7310ac73e
    ('init/main: add checks for the return value of memblock_alloc*()')(CVE-2024-26988)

    In the Linux kernel, the following vulnerability has been resolved: clk: Fix clk_core_get NULL dereference
    It is possible for clk_core_get to dereference a NULL in the following sequence: clk_core_get()
    of_clk_get_hw_from_clkspec() __of_clk_get_hw_from_provider() __clk_get_hw() __clk_get_hw() can return NULL
    which is dereferenced by clk_core_get() at hw-core. Prior to commit dde4eff47c82 ('clk: Look for
    parents with clkdev based clk_lookups') the check IS_ERR_OR_NULL() was performed which would have caught
    the NULL. Reading the description of this function it talks about returning NULL but that cannot be so at
    the moment. Update the function to check for hw before dereferencing it and return NULL if hw is
    NULL.(CVE-2024-27038)

    In the Linux kernel, the following vulnerability has been resolved: geneve: make sure to pull inner header
    in geneve_rx() syzbot triggered a bug in geneve_rx() [1] Issue is similar to the one I fixed in commit
    8d975c15c0cd ('ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()') We have to save skb-
    network_header in a temporary variable in order to be able to recompute the network_header pointer
    after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure the needed headers are in skb-
    head.(CVE-2024-26857)

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

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27075)

    In the Linux kernel, the following vulnerability has been resolved: nouveau: fix instmem race condition
    around ptr stores Running a lot of VK CTS in parallel against nouveau, once every few hours you might see
    something like this crash. BUG: kernel NULL pointer dereference, address: 0000000000000008 PGD
    8000000114e6e067 P4D 8000000114e6e067 PUD 109046067 PMD 0 Oops: 0000.(CVE-2024-26984)

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

    In the Linux kernel, the following vulnerability has been resolved: RDMA/mlx5: Fix fortify source warning
    while accessing Eth segment(CVE-2024-26907)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix a use-after-free There
    are two .exit_cmd_priv implementations. Both implementations use resources associated with the SCSI host.
    Make sure that these resources are still available when .exit_cmd_priv is called by waiting inside
    scsi_remove_host() until the tag set has been freed.(CVE-2022-48666)

    In the Linux kernel, the following vulnerability has been resolved: scsi: target: core: Add TMF to
    tmr_list handling An abort that is responded to by iSCSI itself is added to tmr_list but does not go to
    target core. A LUN_RESET that goes through tmr_list takes a refcounter on the abort and waits for
    completion. However, the abort will be never complete because it was not started in target
    core.(CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved: thermal: intel: hfi: Add syscore
    callbacks for system-wide PM The kernel allocates a memory buffer and provides its location to the
    hardware, which uses it to update the HFI table. This allocation occurs during boot and remains constant
    throughout runtime. When resuming from hibernation, the restore kernel allocates a second memory buffer
    and reprograms the HFI hardware with the new location as part of a normal boot. The location of the second
    memory buffer may differ from the one allocated by the image kernel. When the restore kernel transfers
    control to the image kernel, its HFI buffer becomes invalid, potentially leading to memory corruption if
    the hardware writes to it (the hardware continues to use the buffer from the restore kernel). It is also
    possible that the hardware 'forgets' the address of the memory buffer when resuming from 'deep' suspend.
    Memory corruption may also occur in such a scenario. To prevent the described memory corruption, disable
    HFI when preparing to suspend or hibernate. Enable it when resuming. Add syscore callbacks to handle the
    package of the boot CPU (packages of non-boot CPUs are handled via CPU offline). Syscore ops always run on
    the boot CPU. Additionally, HFI only needs to be disabled during 'deep' suspend and hibernation. Syscore
    ops only run in these cases.(CVE-2024-26646)

    In the Linux kernel, the following vulnerability has been resolved: i40e: Do not allow untrusted VF to
    remove administratively set MAC Currently when PF administratively sets VF's MAC address and the VF is put
    down (VF tries to delete all MACs) then the MAC is removed from MAC filters and primary VF MAC is zeroed.
    Do not allow untrusted VF to remove primary MAC when it was set administratively by PF.(CVE-2024-26830)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: release mutex
    after nft_gc_seq_end from abort path The commit mutex should not be released during the critical section
    between nft_gc_seq_begin() and nft_gc_seq_end(), otherwise, async GC worker could collect expired objects
    and get the released commit lock within the same GC sequence. nf_tables_module_autoload() temporarily
    releases the mutex to load module dependencies, then it goes back to replay the transaction again. Move it
    at the end of the abort phase after nft_gc_seq_end() is called.(CVE-2024-26925)

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

    In the Linux kernel, the following vulnerability has been resolved: cifs: fix underflow in
    parse_server_interfaces() In this loop, we step through the buffer and after each item we check if the
    size_left is greater than the minimum size we need. However, the problem is that 'bytes_left' is type
    ssize_t while sizeof() is type size_t. That means that because of type promotion, the comparison is done
    as an unsigned and if we have negative bytes left the loop continues instead of ending.(CVE-2024-26828)

    Information exposure through microarchitectural state after transient execution from some register files
    for some Intel(R) Atom(R) Processors may allow an authenticated user to potentially enable information
    disclosure via local access.(CVE-2023-28746)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2352
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bef78032");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

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
