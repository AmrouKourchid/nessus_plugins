#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-809.
##

include('compat.inc');

if (description)
{
  script_id(214608);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2023-52926",
    "CVE-2024-27407",
    "CVE-2024-41014",
    "CVE-2024-42252",
    "CVE-2024-43098",
    "CVE-2024-45828",
    "CVE-2024-47745",
    "CVE-2024-48881",
    "CVE-2024-49861",
    "CVE-2024-49926",
    "CVE-2024-49934",
    "CVE-2024-50055",
    "CVE-2024-50121",
    "CVE-2024-50146",
    "CVE-2024-50248",
    "CVE-2024-50258",
    "CVE-2024-50275",
    "CVE-2024-52332",
    "CVE-2024-53099",
    "CVE-2024-53105",
    "CVE-2024-53125",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53146",
    "CVE-2024-53157",
    "CVE-2024-53164",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53175",
    "CVE-2024-53194",
    "CVE-2024-53196",
    "CVE-2024-53198",
    "CVE-2024-53206",
    "CVE-2024-53210",
    "CVE-2024-53214",
    "CVE-2024-53217",
    "CVE-2024-53233",
    "CVE-2024-53240",
    "CVE-2024-53680",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56581",
    "CVE-2024-56582",
    "CVE-2024-56584",
    "CVE-2024-56587",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56603",
    "CVE-2024-56606",
    "CVE-2024-56610",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56625",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56642",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56658",
    "CVE-2024-56660",
    "CVE-2024-56665",
    "CVE-2024-56672",
    "CVE-2024-56675",
    "CVE-2024-56687",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56709",
    "CVE-2024-56716",
    "CVE-2024-56720",
    "CVE-2024-56739",
    "CVE-2024-56745",
    "CVE-2024-56751",
    "CVE-2024-56755",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56770",
    "CVE-2024-56774",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56783",
    "CVE-2024-57798",
    "CVE-2024-57841",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2024-57882",
    "CVE-2024-57884",
    "CVE-2024-57890",
    "CVE-2024-57896",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57903",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946",
    "CVE-2025-21629"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2025-809)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-809 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    IORING_OP_READ did not correctly consume the provided buffer list when (CVE-2023-52926)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Fixed overflow check in mi_enum_attr() (CVE-2024-27407)

    In the Linux kernel, the following vulnerability has been resolved:

    xfs: add bounds checking to xlog_recover_process_data (CVE-2024-41014)

    In the Linux kernel, the following vulnerability has been resolved:

    closures: Change BUG_ON() to WARN_ON() (CVE-2024-42252)

    In the Linux kernel, the following vulnerability has been resolved:

    i3c: Use i3cdev->desc->info instead of calling i3c_device_get_info() to avoid deadlock (CVE-2024-43098)

    In the Linux kernel, the following vulnerability has been resolved:

    i3c: mipi-i3c-hci: Mask ring interrupts before ring stop request (CVE-2024-45828)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: call the security_mmap_file() LSM hook in remap_file_pages() (CVE-2024-47745)

    In the Linux kernel, the following vulnerability has been resolved:

    bcache: revert replacing IS_ERR_OR_NULL with IS_ERR again (CVE-2024-48881)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix helper writes to read-only maps (CVE-2024-49861)

    In the Linux kernel, the following vulnerability has been resolved:

    rcu-tasks: Fix access non-existent percpu rtpcp variable in rcu_tasks_need_gpcb() (CVE-2024-49926)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/inode: Prevent dump_mapping() accessing invalid dentry.d_name.name (CVE-2024-49934)

    In the Linux kernel, the following vulnerability has been resolved:

    driver core: bus: Fix double free in driver API bus_register() (CVE-2024-50055)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: cancel nfsd_shrinker_work using sync mode in nfs4_state_shutdown_net (CVE-2024-50121)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Don't call cleanup on profile rollback failure (CVE-2024-50146)

    In the Linux kernel, the following vulnerability has been resolved:

    ntfs3: Add bounds checking to mi_enum_attr() (CVE-2024-50248)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix crash when config small gso_max_size/gso_ipv4_max_size (CVE-2024-50258)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64/sve: Discard stale CPU state when handling SVE traps (CVE-2024-50275)

    In the Linux kernel, the following vulnerability has been resolved:

    igb: Fix potential invalid memory access in igb_init_module() (CVE-2024-52332)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Check validity of link->type in bpf_link_show_fdinfo() (CVE-2024-53099)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: page_alloc: move mlocked flag clearance into free_pages_prepare() (CVE-2024-53105)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: sync_linked_regs() must preserve subreg_def (CVE-2024-53125)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: ipset: add missing range check in bitmap_ip_uadt (CVE-2024-53141)

    In the Linux kernel, the following vulnerability has been resolved:

    initramfs: avoid filename buffer overrun (CVE-2024-53142)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSD: Prevent a potential integer overflow (CVE-2024-53146)

    In the Linux kernel, the following vulnerability has been resolved:

    firmware: arm_scpi: Check the DVFS OPP count returned by the firmware (CVE-2024-53157)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: fix ordering of qlen adjustment (CVE-2024-53164)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSv4.0: Fix a use-after-free problem in the asynchronous open() (CVE-2024-53173)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: make sure cache entry active before cache_show (CVE-2024-53174)

    In the Linux kernel, the following vulnerability has been resolved:

    ipc: fix memleak if msg_init_ns failed in create_ipc_ns (CVE-2024-53175)

    In the Linux kernel, the following vulnerability has been resolved:

    PCI: Fix use-after-free of slot->bus on hot remove (CVE-2024-53194)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: arm64: Don't retire aborted MMIO instruction (CVE-2024-53196)

    In the Linux kernel, the following vulnerability has been resolved:

    xen: Fix the issue of resource not being properly released in xenbus_dev_probe() (CVE-2024-53198)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: Fix use-after-free of nreq in reqsk_timer_handler(). (CVE-2024-53206)

    In the Linux kernel, the following vulnerability has been resolved:

    s390/iucv: MSG_PEEK causes memory leak in iucv_sock_destruct() (CVE-2024-53210)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: Properly hide first-in-list PCIe extended capability (CVE-2024-53214)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSD: Prevent NULL dereference in nfsd4_process_cb_update() (CVE-2024-53217)

    In the Linux kernel, the following vulnerability has been resolved:

    unicode: Fix utf8_load() error path (CVE-2024-53233)

    In the Linux kernel, the following vulnerability has been resolved:

    xen/netfront: fix crash when removing device (CVE-2024-53240)

    In the Linux kernel, the following vulnerability has been resolved:

    ipvs: fix UB due to uninitialized stack access in ip_vs_protocol_init() (CVE-2024-53680)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: x86: Play nice with protected guests in complete_hypercall_exit() (CVE-2024-55881)

    In the Linux kernel, the following vulnerability has been resolved:

    Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet (CVE-2024-55916)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/modes: Avoid divide by zero harder in drm_mode_vrefresh() (CVE-2024-56369)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: make sure exp active before svc_export_show (CVE-2024-56558)

    In the Linux kernel, the following vulnerability has been resolved:

    i3c: master: Fix miss free init_dyn_addr at i3c_master_put_i3c_addrs() (CVE-2024-56562)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/arm-smmu: Defer probe of clients after smmu device bound (CVE-2024-56568)

    In the Linux kernel, the following vulnerability has been resolved:

    ftrace: Fix regression with module command in stack_trace_filter (CVE-2024-56569)

    In the Linux kernel, the following vulnerability has been resolved:

    ovl: Filter invalid inodes with missing lookup function (CVE-2024-56570)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: ref-verify: fix use-after-free after invalid ref action (CVE-2024-56581)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix use-after-free in btrfs_encoded_read_endio() (CVE-2024-56582)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring/tctx: work around xa_store() allocation error issue (CVE-2024-56584)

    In the Linux kernel, the following vulnerability has been resolved:

    leds: class: Protect brightness_show() with led_cdev->led_access mutex (CVE-2024-56587)

    In the Linux kernel, the following vulnerability has been resolved:

    net: inet6: do not leave a dangling sk pointer in inet6_create() (CVE-2024-56600)

    In the Linux kernel, the following vulnerability has been resolved:

    net: inet: do not leave a dangling sk pointer in inet_create() (CVE-2024-56601)

    In the Linux kernel, the following vulnerability has been resolved:

    net: af_can: do not leave a dangling sk pointer in can_create() (CVE-2024-56603)

    In the Linux kernel, the following vulnerability has been resolved:

    af_packet: avoid erroring out after sock_init_data() in packet_create() (CVE-2024-56606)

    In the Linux kernel, the following vulnerability has been resolved:

    kcsan: Turn report_filterlist_lock into a raw_spinlock (CVE-2024-56610)

    In the Linux kernel, the following vulnerability has been resolved:

    xsk: fix OOB map writes when deleting elements (CVE-2024-56614)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: fix OOB devmap writes when deleting elements (CVE-2024-56615)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/dp_mst: Fix MST sideband message body length check (CVE-2024-56616)

    In the Linux kernel, the following vulnerability has been resolved:

    can: dev: can_set_termination(): allow sleeping GPIOs (CVE-2024-56625)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg (CVE-2024-56633)

    In the Linux kernel, the following vulnerability has been resolved:

    gpio: grgpio: Add NULL check in grgpio_probe (CVE-2024-56634)

    In the Linux kernel, the following vulnerability has been resolved:

    geneve: do not assume mac header is set in geneve_xmit_skb() (CVE-2024-56636)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: ipset: Hold module reference while requesting a module (CVE-2024-56637)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: Fix use-after-free of kernel socket in cleanup_bearer(). (CVE-2024-56642)

    In the Linux kernel, the following vulnerability has been resolved:

    net/ipv6: release expired exception dst cached in socket (CVE-2024-56644)

    In the Linux kernel, the following vulnerability has been resolved:

    can: j1939: j1939_session_new(): fix skb reference counting (CVE-2024-56645)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hsr: avoid potential out-of-bound access in fill_frame_info() (CVE-2024-56648)

    In the Linux kernel, the following vulnerability has been resolved:

    net: defer final 'struct net' free in netns dismantle (CVE-2024-56658)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: DR, prevent potential error pointer dereference (CVE-2024-56660)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf,perf: Fix invalid prog_array access in perf_event_detach_bpf_prog (CVE-2024-56665)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-cgroup: Fix UAF in blkcg_unpin_online() (CVE-2024-56672)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix UAF via mismatching bpf_prog/attachment RCU flavors (CVE-2024-56675)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: musb: Fix hardware lockup on first Rx endpoint request (CVE-2024-56687)

    In the Linux kernel, the following vulnerability has been resolved:

    sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport (CVE-2024-56688)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY (CVE-2024-56690)

    In the Linux kernel, the following vulnerability has been resolved:

    brd: defer automatic disk creation until module initialization succeeds (CVE-2024-56693)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: fix recursive lock when verdict program return SK_PASS (CVE-2024-56694)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: check if iowq is killed before queuing (CVE-2024-56709)

    In the Linux kernel, the following vulnerability has been resolved:

    netdevsim: prevent bad user input in nsim_dev_health_break_write() (CVE-2024-56716)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf, sockmap: Several fixes to bpf_msg_pop_data (CVE-2024-56720)

    In the Linux kernel, the following vulnerability has been resolved:

    rtc: check if __rtc_read_time was successful in rtc_timer_do_work() (CVE-2024-56739)

    In the Linux kernel, the following vulnerability has been resolved:

    PCI: Fix reset_method_store() memory leak (CVE-2024-56745)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: release nexthop on device removal

    The CI is hitting some aperiodic hangup at device removal time in thepmtu.sh self-test:

    unregister_netdevice: waiting for veth_A-R1 to become free. Usage count = 6ref_tracker:
    veth_A-R1@ffff888013df15d8 has 1/5 users atdst_init+0x84/0x4a0dst_alloc+0x97/0x150ip6_dst_alloc+0x23/0x90i
    p6_rt_pcpu_alloc+0x1e6/0x520ip6_pol_route+0x56f/0x840fib6_rule_lookup+0x334/0x630ip6_route_output_flags+0x
    259/0x480ip6_dst_lookup_tail.constprop.0+0x5c2/0x940ip6_dst_lookup_flow+0x88/0x190udp_tunnel6_dst_lookup+0
    x2a7/0x4c0vxlan_xmit_one+0xbde/0x4a50 [vxlan]vxlan_xmit+0x9ad/0xf20 [vxlan]dev_hard_start_xmit+0x10e/0x360
    __dev_queue_xmit+0xf95/0x18c0arp_solicit+0x4a2/0xe00neigh_probe+0xaa/0xf0

    While the first suspect is the dst_cache, explicitly tracking the dstowing the last device reference via
    probes proved such dst is held bythe nexthop in the originating fib6_info.

    Similar to commit f5b51fe804ec (ipv6: route: purge exception onremoval), we need to explicitly release
    the originating fib info whendisconnecting a to-be-removed device from a live ipv6 dst: move thefib6_info
    cleanup into ip6_dst_ifdown().

    Tested running:

    ./pmtu.sh cleanup_ipv6_exception

    in a tight loop for more than 400 iterations with no spat, running anunpatched kernel  I observed a splat
    every ~10 iterations. (CVE-2024-56751)

    In the Linux kernel, the following vulnerability has been resolved:

    netfs/fscache: Add a memory barrier for FSCACHE_VOLUME_CREATING (CVE-2024-56755)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme-pci: fix freeing of the HMB descriptor table (CVE-2024-56756)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix use-after-free when COWing tree bock and tracing is enabled (CVE-2024-56759)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Prevent bad count for tracing_cpumask_write (CVE-2024-56763)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: netem: account for backlog updates from child qdisc (CVE-2024-56770)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: add a sanity check for btrfs root in btrfs_search_slot() (CVE-2024-56774)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: fix nfs4_openowner leak when concurrent nfsd4_open occur (CVE-2024-56779)

    In the Linux kernel, the following vulnerability has been resolved:

    quota: flush quota_release_work upon quota writeback (CVE-2024-56780)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_socket: remove WARN_ON_ONCE on maximum cgroup level (CVE-2024-56783)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req() (CVE-2024-57798)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix memory leak in tcp_conn_request() (CVE-2024-57841)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL (CVE-2024-57874)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/dp_mst: Fix resetting msg rx state after topology removal (CVE-2024-57876)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: fix TCP options overflow. (CVE-2024-57882)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim() (CVE-2024-57884)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/uverbs: Prevent integer overflow issue (CVE-2024-57890)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount (CVE-2024-57896)

    In the Linux kernel, the following vulnerability has been resolved:

    ila: serialize calls to nf_register_net_hooks() (CVE-2024-57900)

    In the Linux kernel, the following vulnerability has been resolved:

    af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK (CVE-2024-57901)

    In the Linux kernel, the following vulnerability has been resolved:

    af_packet: fix vlan_get_tci() vs MSG_PEEK (CVE-2024-57902)

    In the Linux kernel, the following vulnerability has been resolved:

    net: restrict SO_REUSEPORT to inet sockets (CVE-2024-57903)

    In the Linux kernel, the following vulnerability has been resolved:

    selinux: ignore unknown extended permissions (CVE-2024-57931)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sctp: Prevent autoclose integer overflow in sctp_association_init() (CVE-2024-57938)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio-blk: don't keep queue frozen during system suspend (CVE-2024-57946)

    In the Linux kernel, the following vulnerability has been resolved:

    net: reenable NETIF_F_IPV6_CSUM offload for BIG TCP packets (CVE-2025-21629)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52926.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27407.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-41014.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-42252.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-43098.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45828.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47745.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-48881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49861.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49926.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49934.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50121.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50248.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50258.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50275.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-52332.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53105.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53157.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53164.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53173.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53174.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53194.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53198.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53210.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53214.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53217.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53233.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53240.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53680.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-55881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-55916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56369.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56558.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56562.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56568.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56569.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56570.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56581.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56582.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56584.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56587.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56600.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56601.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56606.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56610.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56614.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56615.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56633.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56634.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56636.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56637.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56642.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56644.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56645.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56648.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56658.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56660.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56665.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56687.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56688.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56690.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56694.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56709.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56739.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56745.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56751.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56755.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56756.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56759.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56770.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56783.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57798.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57874.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57876.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57884.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57890.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57896.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57900.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57901.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57902.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57903.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21629.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.6.20250123' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57900");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.124-134.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-52926", "CVE-2024-27407", "CVE-2024-41014", "CVE-2024-42252", "CVE-2024-43098", "CVE-2024-45828", "CVE-2024-47745", "CVE-2024-48881", "CVE-2024-49861", "CVE-2024-49926", "CVE-2024-49934", "CVE-2024-50055", "CVE-2024-50121", "CVE-2024-50146", "CVE-2024-50248", "CVE-2024-50258", "CVE-2024-50275", "CVE-2024-52332", "CVE-2024-53099", "CVE-2024-53105", "CVE-2024-53125", "CVE-2024-53141", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53157", "CVE-2024-53164", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53175", "CVE-2024-53194", "CVE-2024-53196", "CVE-2024-53198", "CVE-2024-53206", "CVE-2024-53210", "CVE-2024-53214", "CVE-2024-53217", "CVE-2024-53233", "CVE-2024-53240", "CVE-2024-53680", "CVE-2024-55881", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56558", "CVE-2024-56562", "CVE-2024-56568", "CVE-2024-56569", "CVE-2024-56570", "CVE-2024-56581", "CVE-2024-56582", "CVE-2024-56584", "CVE-2024-56587", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56603", "CVE-2024-56606", "CVE-2024-56610", "CVE-2024-56614", "CVE-2024-56615", "CVE-2024-56616", "CVE-2024-56625", "CVE-2024-56633", "CVE-2024-56634", "CVE-2024-56636", "CVE-2024-56637", "CVE-2024-56642", "CVE-2024-56644", "CVE-2024-56645", "CVE-2024-56648", "CVE-2024-56658", "CVE-2024-56660", "CVE-2024-56665", "CVE-2024-56672", "CVE-2024-56675", "CVE-2024-56687", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56693", "CVE-2024-56694", "CVE-2024-56709", "CVE-2024-56716", "CVE-2024-56720", "CVE-2024-56739", "CVE-2024-56745", "CVE-2024-56751", "CVE-2024-56755", "CVE-2024-56756", "CVE-2024-56759", "CVE-2024-56763", "CVE-2024-56770", "CVE-2024-56774", "CVE-2024-56779", "CVE-2024-56780", "CVE-2024-56783", "CVE-2024-57798", "CVE-2024-57841", "CVE-2024-57874", "CVE-2024-57876", "CVE-2024-57882", "CVE-2024-57884", "CVE-2024-57890", "CVE-2024-57896", "CVE-2024-57900", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57946", "CVE-2025-21629");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2025-809");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.124-134.200-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.124-134.200-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.124-134.200.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
