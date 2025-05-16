#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235400);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id(
    "CVE-2022-48720",
    "CVE-2023-52923",
    "CVE-2024-47141",
    "CVE-2024-47794",
    "CVE-2024-47809",
    "CVE-2024-49569",
    "CVE-2024-53164",
    "CVE-2024-53168",
    "CVE-2024-53195",
    "CVE-2024-53217",
    "CVE-2024-53685",
    "CVE-2024-54680",
    "CVE-2024-54683",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56568",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56644",
    "CVE-2024-56769",
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
    "CVE-2025-21649",
    "CVE-2025-21650",
    "CVE-2025-21651",
    "CVE-2025-21653",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21667",
    "CVE-2025-21669",
    "CVE-2025-21682",
    "CVE-2025-21683",
    "CVE-2025-21694"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2025-1421)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    filemap: avoid truncating 64-bit offset to 32 bits(CVE-2025-21665)

    iomap: avoid avoid truncating 64-bit offset to 32 bits(CVE-2025-21667)

    fs/proc: fix softlockup in __read_vmcore (part 2).(CVE-2025-21694)

    net: hns3: don't auto enable misc vector(CVE-2025-21651)

    netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

    net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute(CVE-2025-21653)

    netfilter: ipset: Hold module reference while requesting a module(CVE-2024-56637)

    sctp: sysctl: auth_enable: avoid using current-nsproxy(CVE-2025-21638)

    sctp: sysctl: cookie_hmac_alg: avoid using current-nsproxy(CVE-2025-21640)

    af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK(CVE-2024-57901)

    af_packet: fix vlan_get_tci() vs MSG_PEEK(CVE-2024-57902)

    net: sched: fix ordering of qlen adjustment(CVE-2024-53164)

    geneve: do not assume mac header is set in geneve_xmit_skb().(CVE-2024-56636)

    RDMA/rxe: Remove the direct link to net_device(CVE-2024-57795)

    net/ipv6: release expired exception dst cached in socket(CVE-2024-56644)

    NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

    iommu/arm-smmu: Defer probe of clients after smmu device bound(CVE-2024-56568)

    net/sctp: Prevent autoclose integer overflow in sctp_association_init().(CVE-2024-57938)

    dlm: fix possible lkb_resource null dereference(CVE-2024-47809)

    vsock/virtio: discard packets if the transport changes(CVE-2025-21669)

    vsock: prevent null-ptr-deref in vsock_*[has_data|has_space](CVE-2025-21666)

    netfilter: nf_tables: adapt set backend to use GC transaction API(CVE-2023-52923)

    RDMA/uverbs: Prevent integer overflow issue(CVE-2024-57890)

    pinmux: Use sequential access to access desc-pinmux data(CVE-2024-47141)

    drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req().(CVE-2024-57798)

    selinux: ignore unknown extended permissions(CVE-2024-57931)

    eth: bnxt: always recalculate features after XDP clearing, fix null-deref(CVE-2025-21682)

    bpf: Fix bpf_sk_select_reuseport() memory leak(CVE-2025-21683)

    net: restrict SO_REUSEPORT to inet sockets(CVE-2024-57903)

    sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket(CVE-2024-53168)

    net: macsec: Fix offload support for NETDEV_UNREGISTER event(CVE-2022-48720)

    netfilter: nf_set_pipapo: fix initial map fill(CVE-2024-57947)

    KVM: arm64: Get rid of userspace_irqchip_in_use(CVE-2024-53195)

    virtio-blk: don't keep queue frozen during system suspend(CVE-2024-57946)

    workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker(CVE-2024-57888)

    mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim().(CVE-2024-57884)

    net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue(CVE-2025-21650)

    ceph: give up on paths longer than PATH_MAX(CVE-2024-53685)

    net: hns3: fix kernel crash when 1588 is sent on HIP08 devices(CVE-2025-21649)

    drm/dp_mst: Fix resetting msg rx state after topology removal(CVE-2024-57876)

    arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL(CVE-2024-57874)

    mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

    Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet(CVE-2024-55916)

    scsi: megaraid_sas: Fix for a potential deadlock(CVE-2024-57807)

    netfilter: IDLETIMER: Fix for possible ABBA deadlock(CVE-2024-54683)

    bpf: Prevent tailcall infinite loop caused by freplace(CVE-2024-47794)

    fs: relax assertions on failure to encode file handles(CVE-2024-57924)

    smb: client: fix TCP timers deadlock after rmmod(CVE-2024-54680)

    nvme-rdma: unquiesce admin_q before destroy it(CVE-2024-49569)

    drm/modes: Avoid divide by zero harder in drm_mode_vrefresh().(CVE-2024-56369)

    media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg(CVE-2024-56769)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1421
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0d54455");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

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
  "bpftool-5.10.0-136.12.0.86.h2482.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h2482.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h2482.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h2482.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h2482.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h2482.eulerosv2r12"
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
