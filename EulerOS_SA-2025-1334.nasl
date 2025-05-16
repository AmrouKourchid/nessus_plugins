#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233614);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2022-48987",
    "CVE-2024-43098",
    "CVE-2024-47794",
    "CVE-2024-49569",
    "CVE-2024-50210",
    "CVE-2024-53103",
    "CVE-2024-53135",
    "CVE-2024-53146",
    "CVE-2024-53157",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53179",
    "CVE-2024-53185",
    "CVE-2024-53187",
    "CVE-2024-53194",
    "CVE-2024-53195",
    "CVE-2024-53214",
    "CVE-2024-53219",
    "CVE-2024-53224",
    "CVE-2024-53685",
    "CVE-2024-54680",
    "CVE-2024-54683",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56549",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56572",
    "CVE-2024-56574",
    "CVE-2024-56583",
    "CVE-2024-56584",
    "CVE-2024-56587",
    "CVE-2024-56588",
    "CVE-2024-56592",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56606",
    "CVE-2024-56611",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56623",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56642",
    "CVE-2024-56647",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56662",
    "CVE-2024-56664",
    "CVE-2024-56672",
    "CVE-2024-56688",
    "CVE-2024-56690",
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
    "CVE-2024-57807",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2024-57883",
    "CVE-2024-57884",
    "CVE-2024-57888",
    "CVE-2024-57889",
    "CVE-2024-57924",
    "CVE-2024-57946",
    "CVE-2025-21649",
    "CVE-2025-21650",
    "CVE-2025-21656"
  );

  script_name(english:"EulerOS 2.0 SP13 : kernel (EulerOS-SA-2025-1334)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    i3c: Use i3cdev-desc-info instead of calling i3c_device_get_info() to avoid deadlock(CVE-2024-43098)

    KVM: arm64: Get rid of userspace_irqchip_in_use(CVE-2024-53195)

    virtio-blk: don't keep queue frozen during system suspend(CVE-2024-57946)

    workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker(CVE-2024-57888)

    mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim().(CVE-2024-57884)

    net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue(CVE-2025-21650)

    ceph: give up on paths longer than PATH_MAX(CVE-2024-53685)

    net: hns3: fix kernel crash when 1588 is sent on HIP08 devices(CVE-2025-21649)

    drm/dp_mst: Fix resetting msg rx state after topology removal(CVE-2024-57876)

    arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL(CVE-2024-57874)

    hwmon: (drivetemp) Fix driver producing garbage data when SCSI errors occur(CVE-2025-21656)

    mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

    Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet(CVE-2024-55916)

    netfilter: IDLETIMER: Fix for possible ABBA deadlock(CVE-2024-54683)

    scsi: megaraid_sas: Fix for a potential deadlock(CVE-2024-57807)

    bpf: Prevent tailcall infinite loop caused by freplace(CVE-2024-47794)

    fs: relax assertions on failure to encode file handles(CVE-2024-57924)

    smb: client: fix TCP timers deadlock after rmmod(CVE-2024-54680)

    media: platform: allegro-dvt: Fix possible memory leak in allocate_buffers_internal().(CVE-2024-56572)

    net/sched: netem: account for backlog updates from child qdisc(CVE-2024-56770)

    nvme-rdma: unquiesce admin_q before destroy it(CVE-2024-49569)

    nfsd: fix nfs4_openowner leak when concurrent nfsd4_open occur(CVE-2024-56779)

    netdevsim: prevent bad user input in nsim_dev_health_break_write().(CVE-2024-56716)

    xsk: fix OOB map writes when deleting elements(CVE-2024-56614)

    bpf, sockmap: Several fixes to bpf_msg_pop_data(CVE-2024-56720)

    net: inet6: do not leave a dangling sk pointer in inet6_create().(CVE-2024-56600)

    af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

    NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

    pinctrl: mcp23s08: Fix sleeping in atomic context due to regmap locking(CVE-2024-57889)

    drm/modes: Avoid divide by zero harder in drm_mode_vrefresh().(CVE-2024-56369)

    scsi: hisi_sas: Create all dump files during debugfs initialization(CVE-2024-56588)

    scsi: qla2xxx: Fix use after free on unload(CVE-2024-56623)

    RDMA/hns: Fix cpu stuck caused by printings during reset(CVE-2024-56722)

    bpf: Call free_htab_elem() after htab_unlock_bucket().(CVE-2024-56592)

    ipv6: release nexthop on device removal(CVE-2024-56751)

    scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb()(CVE-2024-56747)

    NFSD: Prevent a potential integer overflow(CVE-2024-53146)

    net: Fix icmp host relookup triggering ip_rt_bug(CVE-2024-56647)

    hv_sock: Initializing vsk-trans to NULL to prevent a dangling pointer(CVE-2024-53103)

    acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl(CVE-2024-56662)

    blk-cgroup: Fix UAF in blkcg_unpin_online().(CVE-2024-56672)

    net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

    nvme-pci: fix freeing of the HMB descriptor table(CVE-2024-56756)

    media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg(CVE-2024-56769)

    tracing: Prevent bad count for tracing_cpumask_write(CVE-2024-56763)

    netfilter: x_tables: fix LED ID check in led_tg_check().(CVE-2024-56650)

    quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

    smb: client: fix use-after-free of signing key(CVE-2024-53179)

    crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY(CVE-2024-56690)

    firmware: arm_scpi: Check the DVFS OPP count returned by the firmware(CVE-2024-53157)

    posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime().(CVE-2024-50210)

    tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg(CVE-2024-56633)

    SUNRPC: make sure cache entry active before cache_show(CVE-2024-53174)

    io_uring/tctx: work around xa_store() allocation error issue(CVE-2024-56584)

    PCI: Fix use-after-free of slot-bus on hot remove(CVE-2024-53194)

    media: v4l2-dv-timings.c: fix too strict blanking sanity checks(CVE-2022-48987)

    virtiofs: use pages instead of pointer for kernel direct IO(CVE-2024-53219)

    mm/mempolicy: fix migrate_to_node() assuming there is at least one VMA in a MM(CVE-2024-56611)

    rtc: check if __rtc_read_time was successful in rtc_timer_do_work()(CVE-2024-56739)

    ipv6: Fix soft lockups in fib6_select_path under high next hop churn(CVE-2024-56703)

    sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport(CVE-2024-56688)

    tipc: Fix use-after-free of kernel socket in cleanup_bearer().(CVE-2024-56642)

    net: inet: do not leave a dangling sk pointer in inet_create().(CVE-2024-56601)

    bpf, sockmap: Fix race between element replace and close()(CVE-2024-56664)

    scsi: sg: Fix slab-use-after-free read in sg_release()(CVE-2024-56631)

    RDMA/mlx5: Move events notifier registration to be after device registration(CVE-2024-53224)

    io_uring: check for overflows in io_pin_pages(CVE-2024-53187)

    sched/deadline: Fix warning in migrate_enable for boosted tasks(CVE-2024-56583)

    leds: class: Protect brightness_show() with led_cdev-led_access mutex(CVE-2024-56587)

    io_uring: check if iowq is killed before queuing(CVE-2024-56709)

    bpf: fix OOB devmap writes when deleting elemen(CVE-2024-56615)

    vfio/pci: Properly hide first-in-list PCIe extended capability(CVE-2024-53214)

    smb: client: fix NULL ptr deref in crypto_aead_setkey().(CVE-2024-53185)

    cachefiles: Fix NULL pointer dereference in object-file At present, the object-file has the NULL
    pointer dereference problem in ondemand-mode.(CVE-2024-56549)

    ovl: Filter invalid inodes with missing lookup function(CVE-2024-56570)

    scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb().(CVE-2024-56748)

    ftrace: Fix regression with module command in stack_trace_filter(CVE-2024-56569)

    media: ts2020: fix null-ptr-deref in ts2020_probe().(CVE-2024-56574)

    KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN(CVE-2024-53135)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1334
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ab4db7a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP13");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(13)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP13");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP13", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-182.0.0.95.h2572.eulerosv2r13",
  "kernel-5.10.0-182.0.0.95.h2572.eulerosv2r13",
  "kernel-abi-stablelists-5.10.0-182.0.0.95.h2572.eulerosv2r13",
  "kernel-tools-5.10.0-182.0.0.95.h2572.eulerosv2r13",
  "kernel-tools-libs-5.10.0-182.0.0.95.h2572.eulerosv2r13",
  "python3-perf-5.10.0-182.0.0.95.h2572.eulerosv2r13"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"13", reference:pkg)) flag++;

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
