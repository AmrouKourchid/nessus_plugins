#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205968);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id(
    "CVE-2021-47037",
    "CVE-2021-47070",
    "CVE-2021-47076",
    "CVE-2021-47094",
    "CVE-2021-47101",
    "CVE-2021-47105",
    "CVE-2021-47182",
    "CVE-2021-47212",
    "CVE-2021-47265",
    "CVE-2021-47427",
    "CVE-2021-47469",
    "CVE-2022-48651",
    "CVE-2022-48666",
    "CVE-2022-48689",
    "CVE-2022-48692",
    "CVE-2022-48703",
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
    "CVE-2024-26830",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26851",
    "CVE-2024-26855",
    "CVE-2024-26857",
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
    "CVE-2024-26915",
    "CVE-2024-26920",
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
    "CVE-2024-27437",
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

  script_name(english:"EulerOS Virtualization 2.11.1 : kernel (EulerOS-SA-2024-2178)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

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
    8d975c15c0cd (''ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()'') We have to save skb-
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
    (''init/main: add checks for the return value of memblock_alloc*()'')(CVE-2024-26988)

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
    is reserved for no-mapping addresses Since commit a4d5613c4dc6 (''arm: extend pfn_valid to take into
    account freed memory map alignment'') changes the semantics of pfn_valid() to check presence of the memory
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
    Quoting Pablo: add_elem(''00000000'') timeout 100 ms ... add_elem(''0000000X'') timeout 100 ms
    del_elem(''0000000X'') ---------------- delete one that was just added ... add_elem(''00005000'')
    timeout 100 ms 1) nft_pipapo_remove() removes element 0000000X Then, KASAN shows a splat. Looking at the
    remove function there is a chance that we will drop a rule that maps to a non-deactivated element. Removal
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

Tenable has extracted the preceding description block directly from the EulerOS Virtualization kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2178
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6182c8d8");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.1");
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
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
