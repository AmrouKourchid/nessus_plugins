#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2025-061.
##

include('compat.inc');

if (description)
{
  script_id(214614);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-43098",
    "CVE-2024-45828",
    "CVE-2024-48881",
    "CVE-2024-49974",
    "CVE-2024-50055",
    "CVE-2024-50121",
    "CVE-2024-50275",
    "CVE-2024-52332",
    "CVE-2024-53096",
    "CVE-2024-53099",
    "CVE-2024-53113",
    "CVE-2024-53119",
    "CVE-2024-53121",
    "CVE-2024-53122",
    "CVE-2024-53125",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53136",
    "CVE-2024-53138",
    "CVE-2024-53140",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53146",
    "CVE-2024-53157",
    "CVE-2024-53164",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53194",
    "CVE-2024-53198",
    "CVE-2024-53206",
    "CVE-2024-53214",
    "CVE-2024-53217",
    "CVE-2024-53240",
    "CVE-2024-53680",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56568",
    "CVE-2024-56570",
    "CVE-2024-56581",
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
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56716",
    "CVE-2024-56720",
    "CVE-2024-56739",
    "CVE-2024-56745",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56770",
    "CVE-2024-56774",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-57841",
    "CVE-2024-57874",
    "CVE-2024-57884",
    "CVE-2024-57890",
    "CVE-2024-57896",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57903",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2025-061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.176-118.170. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2025-061 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    i3c: Use i3cdev->desc->info instead of calling i3c_device_get_info() to avoid deadlock (CVE-2024-43098)

    In the Linux kernel, the following vulnerability has been resolved:

    i3c: mipi-i3c-hci: Mask ring interrupts before ring stop request (CVE-2024-45828)

    In the Linux kernel, the following vulnerability has been resolved:

    bcache: revert replacing IS_ERR_OR_NULL with IS_ERR again (CVE-2024-48881)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSD: Limit the number of concurrent async COPY operations (CVE-2024-49974)

    In the Linux kernel, the following vulnerability has been resolved:

    driver core: bus: Fix double free in driver API bus_register() (CVE-2024-50055)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: cancel nfsd_shrinker_work using sync mode in nfs4_state_shutdown_net (CVE-2024-50121)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64/sve: Discard stale CPU state when handling SVE traps (CVE-2024-50275)

    In the Linux kernel, the following vulnerability has been resolved:

    igb: Fix potential invalid memory access in igb_init_module() (CVE-2024-52332)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: resolve faulty mmap_region() error path behaviour (CVE-2024-53096)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Check validity of link->type in bpf_link_show_fdinfo() (CVE-2024-53099)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (CVE-2024-53113)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio/vsock: Fix accept_queue memory leak (CVE-2024-53119)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: fs, lock FTE when checking if active (CVE-2024-53121)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (CVE-2024-53122)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: sync_linked_regs() must preserve subreg_def (CVE-2024-53125)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/rockchip: vop: Fix a dereferenced before check warning (CVE-2024-53129)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (CVE-2024-53130)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (CVE-2024-53131)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN (CVE-2024-53135)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: revert mm: shmem: fix data-race in shmem_getattr() (CVE-2024-53136)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: kTLS, Fix incorrect page refcounting (CVE-2024-53138)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: terminate outstanding dump on socket close (CVE-2024-53140)

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

    PCI: Fix use-after-free of slot->bus on hot remove (CVE-2024-53194)

    In the Linux kernel, the following vulnerability has been resolved:

    xen: Fix the issue of resource not being properly released in xenbus_dev_probe() (CVE-2024-53198)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: Fix use-after-free of nreq in reqsk_timer_handler(). (CVE-2024-53206)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: Properly hide first-in-list PCIe extended capability (CVE-2024-53214)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSD: Prevent NULL dereference in nfsd4_process_cb_update() (CVE-2024-53217)

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

    ovl: Filter invalid inodes with missing lookup function (CVE-2024-56570)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: ref-verify: fix use-after-free after invalid ref action (CVE-2024-56581)

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

    net/ipv6: release expired exception dst cached in socket (CVE-2024-56644)

    In the Linux kernel, the following vulnerability has been resolved:

    can: j1939: j1939_session_new(): fix skb reference counting (CVE-2024-56645)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hsr: avoid potential out-of-bound access in fill_frame_info() (CVE-2024-56648)

    In the Linux kernel, the following vulnerability has been resolved:

    sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport (CVE-2024-56688)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY (CVE-2024-56690)

    In the Linux kernel, the following vulnerability has been resolved:

    brd: defer automatic disk creation until module initialization succeeds (CVE-2024-56693)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: fix recursive lock when verdict program return SK_PASS (CVE-2024-56694)

    In the Linux kernel, the following vulnerability has been resolved:

    netdevsim: prevent bad user input in nsim_dev_health_break_write() (CVE-2024-56716)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf, sockmap: Several fixes to bpf_msg_pop_data (CVE-2024-56720)

    In the Linux kernel, the following vulnerability has been resolved:

    rtc: check if __rtc_read_time was successful in rtc_timer_do_work() (CVE-2024-56739)

    In the Linux kernel, the following vulnerability has been resolved:

    PCI: Fix reset_method_store() memory leak (CVE-2024-56745)

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

    net: fix memory leak in tcp_conn_request() (CVE-2024-57841)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL (CVE-2024-57874)

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

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2025-061.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-43098.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45828.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-48881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50121.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50275.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-52332.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53096.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53113.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53119.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53121.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53122.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53130.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53135.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53140.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53157.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53164.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53173.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53174.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53194.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53198.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53214.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53217.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53240.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53680.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-55881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-55916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56369.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56558.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56562.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56568.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56570.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56581.html");
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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56644.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56645.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56648.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56688.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56690.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56694.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56739.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56745.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56756.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56759.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56770.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57874.html");
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
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.176-118.170");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2024-43098", "CVE-2024-45828", "CVE-2024-48881", "CVE-2024-49974", "CVE-2024-50055", "CVE-2024-50121", "CVE-2024-50275", "CVE-2024-52332", "CVE-2024-53096", "CVE-2024-53099", "CVE-2024-53113", "CVE-2024-53119", "CVE-2024-53121", "CVE-2024-53122", "CVE-2024-53125", "CVE-2024-53129", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53135", "CVE-2024-53136", "CVE-2024-53138", "CVE-2024-53140", "CVE-2024-53141", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53157", "CVE-2024-53164", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53194", "CVE-2024-53198", "CVE-2024-53206", "CVE-2024-53214", "CVE-2024-53217", "CVE-2024-53240", "CVE-2024-53680", "CVE-2024-55881", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56558", "CVE-2024-56562", "CVE-2024-56568", "CVE-2024-56570", "CVE-2024-56581", "CVE-2024-56587", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56603", "CVE-2024-56606", "CVE-2024-56610", "CVE-2024-56614", "CVE-2024-56615", "CVE-2024-56616", "CVE-2024-56625", "CVE-2024-56633", "CVE-2024-56634", "CVE-2024-56636", "CVE-2024-56637", "CVE-2024-56644", "CVE-2024-56645", "CVE-2024-56648", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56693", "CVE-2024-56694", "CVE-2024-56716", "CVE-2024-56720", "CVE-2024-56739", "CVE-2024-56745", "CVE-2024-56756", "CVE-2024-56759", "CVE-2024-56763", "CVE-2024-56770", "CVE-2024-56774", "CVE-2024-56779", "CVE-2024-56780", "CVE-2024-57841", "CVE-2024-57874", "CVE-2024-57884", "CVE-2024-57890", "CVE-2024-57896", "CVE-2024-57900", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57946");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2025-061");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.15"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.176-118.170.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.176-118.170-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.176-118.170-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.176-118.170.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.176-118.170.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
