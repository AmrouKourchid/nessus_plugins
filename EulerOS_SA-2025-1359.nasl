#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234161);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2024-47141",
    "CVE-2024-47794",
    "CVE-2024-47809",
    "CVE-2024-49569",
    "CVE-2024-53093",
    "CVE-2024-53103",
    "CVE-2024-53124",
    "CVE-2024-53125",
    "CVE-2024-53135",
    "CVE-2024-53140",
    "CVE-2024-53146",
    "CVE-2024-53157",
    "CVE-2024-53164",
    "CVE-2024-53168",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53179",
    "CVE-2024-53185",
    "CVE-2024-53187",
    "CVE-2024-53194",
    "CVE-2024-53195",
    "CVE-2024-53214",
    "CVE-2024-53217",
    "CVE-2024-53219",
    "CVE-2024-53224",
    "CVE-2024-53685",
    "CVE-2024-54680",
    "CVE-2024-54683",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56574",
    "CVE-2024-56584",
    "CVE-2024-56587",
    "CVE-2024-56588",
    "CVE-2024-56592",
    "CVE-2024-56593",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56606",
    "CVE-2024-56608",
    "CVE-2024-56611",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56623",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56637",
    "CVE-2024-56642",
    "CVE-2024-56644",
    "CVE-2024-56647",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56662",
    "CVE-2024-56664",
    "CVE-2024-56672",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56694",
    "CVE-2024-56703",
    "CVE-2024-56709",
    "CVE-2024-56716",
    "CVE-2024-56720",
    "CVE-2024-56722",
    "CVE-2024-56739",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56751",
    "CVE-2024-56756",
    "CVE-2024-56763",
    "CVE-2024-56769",
    "CVE-2024-56770",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-57795",
    "CVE-2024-57798",
    "CVE-2024-57807",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2024-57883",
    "CVE-2024-57884",
    "CVE-2024-57888",
    "CVE-2024-57890",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57903",
    "CVE-2024-57924",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946",
    "CVE-2024-57947",
    "CVE-2025-21638",
    "CVE-2025-21640",
    "CVE-2025-21648",
    "CVE-2025-21653",
    "CVE-2025-21662",
    "CVE-2025-21665",
    "CVE-2025-21683",
    "CVE-2025-21693",
    "CVE-2025-21694",
    "CVE-2025-21699"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2025-1359)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    net: fix data-races around sk-sk_forward_alloc(CVE-2024-53124)

    nvme-multipath: defer partition scanning(CVE-2024-53093)

    bpf: sync_linked_regs() must preserve subreg_def(CVE-2024-53125)

    KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN(CVE-2024-53135)

    netlink: terminate outstanding dump on socket close(CVE-2024-53140)

    media: ts2020: fix null-ptr-deref in ts2020_probe().(CVE-2024-56574)

    drm/amd/display: Fix out-of-bounds access in 'dcn21_link_encoder_create'(CVE-2024-56608)

    ftrace: Fix regression with module command in stack_trace_filter(CVE-2024-56569)

    scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb().(CVE-2024-56748)

    ovl: Filter invalid inodes with missing lookup function(CVE-2024-56570)

    smb: client: fix NULL ptr deref in crypto_aead_setkey().(CVE-2024-53185)

    vfio/pci: Properly hide first-in-list PCIe extended capability(CVE-2024-53214)

    bpf: fix OOB devmap writes when deleting elemen(CVE-2024-56615)

    io_uring: check if iowq is killed before queuing(CVE-2024-56709)

    leds: class: Protect brightness_show() with led_cdev-led_access mutex(CVE-2024-56587)

    io_uring: check for overflows in io_pin_pages(CVE-2024-53187)

    RDMA/mlx5: Move events notifier registration to be after device registration(CVE-2024-53224)

    scsi: sg: Fix slab-use-after-free read in sg_release()(CVE-2024-56631)

    bpf, sockmap: Fix race between element replace and close()(CVE-2024-56664)

    net: inet: do not leave a dangling sk pointer in inet_create().(CVE-2024-56601)

    tipc: Fix use-after-free of kernel socket in cleanup_bearer().(CVE-2024-56642)

    sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport(CVE-2024-56688)

    ipv6: Fix soft lockups in fib6_select_path under high next hop churn(CVE-2024-56703)

    rtc: check if __rtc_read_time was successful in rtc_timer_do_work()(CVE-2024-56739)

    mm/mempolicy: fix migrate_to_node() assuming there is at least one VMA in a MM(CVE-2024-56611)

    virtiofs: use pages instead of pointer for kernel direct IO(CVE-2024-53219)

    PCI: Fix use-after-free of slot-bus on hot remove(CVE-2024-53194)

    io_uring/tctx: work around xa_store() allocation error issue(CVE-2024-56584)

    SUNRPC: make sure cache entry active before cache_show(CVE-2024-53174)

    tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg(CVE-2024-56633)

    firmware: arm_scpi: Check the DVFS OPP count returned by the firmware(CVE-2024-53157)

    crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY(CVE-2024-56690)

    smb: client: fix use-after-free of signing key(CVE-2024-53179)

    quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

    netfilter: x_tables: fix LED ID check in led_tg_check().(CVE-2024-56650)

    tracing: Prevent bad count for tracing_cpumask_write(CVE-2024-56763)

    media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg(CVE-2024-56769)

    nvme-pci: fix freeing of the HMB descriptor table(CVE-2024-56756)

    net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

    blk-cgroup: Fix UAF in blkcg_unpin_online().(CVE-2024-56672)

    acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl(CVE-2024-56662)

    hv_sock: Initializing vsk-trans to NULL to prevent a dangling pointer(CVE-2024-53103)

    net: Fix icmp host relookup triggering ip_rt_bug(CVE-2024-56647)

    NFSD: Prevent a potential integer overflow(CVE-2024-53146)

    scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb()(CVE-2024-56747)

    ipv6: release nexthop on device removal(CVE-2024-56751)

    bpf: Call free_htab_elem() after htab_unlock_bucket().(CVE-2024-56592)

    RDMA/hns: Fix cpu stuck caused by printings during reset(CVE-2024-56722)

    scsi: qla2xxx: Fix use after free on unload(CVE-2024-56623)

    scsi: hisi_sas: Create all dump files during debugfs initialization(CVE-2024-56588)

    drm/modes: Avoid divide by zero harder in drm_mode_vrefresh().(CVE-2024-56369)

    NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

    af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

    net: inet6: do not leave a dangling sk pointer in inet6_create().(CVE-2024-56600)

    wifi: brcmfmac: Fix oops due to NULL pointer dereference in brcmf_sdiod_sglist_rw().(CVE-2024-56593)

    bpf, sockmap: Several fixes to bpf_msg_pop_data(CVE-2024-56720)

    xsk: fix OOB map writes when deleting elements(CVE-2024-56614)

    netdevsim: prevent bad user input in nsim_dev_health_break_write().(CVE-2024-56716)

    nfsd: fix nfs4_openowner leak when concurrent nfsd4_open occur(CVE-2024-56779)

    nvme-rdma: unquiesce admin_q before destroy it(CVE-2024-49569)

    net/sched: netem: account for backlog updates from child qdisc(CVE-2024-56770)

    smb: client: fix TCP timers deadlock after rmmod(CVE-2024-54680)

    fs: relax assertions on failure to encode file handles(CVE-2024-57924)

    bpf: Prevent tailcall infinite loop caused by freplace(CVE-2024-47794)

    netfilter: IDLETIMER: Fix for possible ABBA deadlock(CVE-2024-54683)

    scsi: megaraid_sas: Fix for a potential deadlock(CVE-2024-57807)

    Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet(CVE-2024-55916)

    mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

    arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL(CVE-2024-57874)

    drm/dp_mst: Fix resetting msg rx state after topology removal(CVE-2024-57876)

    ceph: give up on paths longer than PATH_MAX(CVE-2024-53685)

    mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim().(CVE-2024-57884)

    workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker(CVE-2024-57888)

    virtio-blk: don't keep queue frozen during system suspend(CVE-2024-57946)

    KVM: arm64: Get rid of userspace_irqchip_in_use(CVE-2024-53195)

    netfilter: nf_set_pipapo: fix initial map fill(CVE-2024-57947)

    sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket(CVE-2024-53168)

    net: restrict SO_REUSEPORT to inet sockets(CVE-2024-57903)

    bpf: Fix bpf_sk_select_reuseport() memory leak(CVE-2025-21683)

    selinux: ignore unknown extended permissions(CVE-2024-57931)

    pinmux: Use sequential access to access desc-pinmux data(CVE-2024-47141)

    drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req().(CVE-2024-57798)

    RDMA/uverbs: Prevent integer overflow issue(CVE-2024-57890)

    dlm: fix possible lkb_resource null dereference(CVE-2024-47809)

    net/sctp: Prevent autoclose integer overflow in sctp_association_init().(CVE-2024-57938)

    iommu/arm-smmu: Defer probe of clients after smmu device bound(CVE-2024-56568)

    NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

    net/ipv6: release expired exception dst cached in socket(CVE-2024-56644)

    RDMA/rxe: Remove the direct link to net_device(CVE-2024-57795)

    af_packet: fix vlan_get_tci() vs MSG_PEEK(CVE-2024-57902)

    net: sched: fix ordering of qlen adjustment(CVE-2024-53164)

    af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK(CVE-2024-57901)

    sctp: sysctl: cookie_hmac_alg: avoid using current-nsproxy(CVE-2025-21640)

    sctp: sysctl: auth_enable: avoid using current-nsproxy(CVE-2025-21638)

    gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag(CVE-2025-21699)

    netfilter: ipset: Hold module reference while requesting a module(CVE-2024-56637)

    net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute(CVE-2025-21653)

    netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

    fs/proc: fix softlockup in __read_vmcore (part 2).(CVE-2025-21694)

    filemap: avoid truncating 64-bit offset to 32 bits(CVE-2025-21665)

    mm: zswap: properly synchronize freeing resources during CPU hotunplug(CVE-2025-21693)

    bpf: fix recursive lock when verdict program return SK_PASS(CVE-2024-56694)

    net/mlx5: Fix variable not being completed when function returns(CVE-2025-21662)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1359
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd7853fc");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  "bpftool-5.10.0-60.18.0.50.h1841.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1841.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1841.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1841.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1841.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1841.eulerosv2r11"
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
