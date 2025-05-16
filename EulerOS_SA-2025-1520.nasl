#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235744);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2021-47634",
    "CVE-2021-47659",
    "CVE-2022-49052",
    "CVE-2022-49053",
    "CVE-2022-49114",
    "CVE-2022-49155",
    "CVE-2022-49259",
    "CVE-2022-49264",
    "CVE-2022-49280",
    "CVE-2022-49307",
    "CVE-2022-49316",
    "CVE-2022-49341",
    "CVE-2022-49370",
    "CVE-2022-49385",
    "CVE-2022-49388",
    "CVE-2022-49395",
    "CVE-2022-49404",
    "CVE-2022-49407",
    "CVE-2022-49414",
    "CVE-2022-49433",
    "CVE-2022-49441",
    "CVE-2022-49447",
    "CVE-2022-49450",
    "CVE-2022-49478",
    "CVE-2022-49526",
    "CVE-2022-49532",
    "CVE-2022-49535",
    "CVE-2022-49538",
    "CVE-2022-49564",
    "CVE-2022-49581",
    "CVE-2022-49620",
    "CVE-2022-49647",
    "CVE-2022-49674",
    "CVE-2022-49687",
    "CVE-2022-49731",
    "CVE-2023-52572",
    "CVE-2024-56606",
    "CVE-2024-56614",
    "CVE-2024-56658",
    "CVE-2024-56780",
    "CVE-2024-57883",
    "CVE-2024-57931",
    "CVE-2024-57977",
    "CVE-2024-57980",
    "CVE-2024-57996",
    "CVE-2025-21648",
    "CVE-2025-21700",
    "CVE-2025-21702",
    "CVE-2025-21719",
    "CVE-2025-21731",
    "CVE-2025-21791",
    "CVE-2025-21796",
    "CVE-2025-21806",
    "CVE-2025-21858"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2025-1520)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    cifs: Fix UAF in cifs_demultiplex_thread().(CVE-2023-52572)

    xsk: fix OOB map writes when deleting elements(CVE-2024-56614)

    net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

    af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

    quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

    mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

    selinux: ignore unknown extended permissions(CVE-2024-57931)

    netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

    net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21700)

    net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21702)

    ubi: Fix race condition between ctrl_cdev_ioctl and ubi_cdev_ioctl(CVE-2021-47634)

    crypto: qat - add param check for DH(CVE-2022-49564)

    nfsd: clear acl_access/acl_default after releasing them(CVE-2025-21796)

    media: uvcvideo: Fix double free in error path(CVE-2024-57980)

    ata: libata-core: fix NULL pointer deref in ata_host_alloc_pinfo().(CVE-2022-49731)

    dm raid: fix accesses beyond end of raid member array(CVE-2022-49674)

    scsi: lpfc: Fix null pointer dereference after failing to issue FLOGI and PLOGI(CVE-2022-49535)

    md/bitmap: don't set sb values if can't pass sanity check(CVE-2022-49526)

    drm/virtio: fix NULL pointer dereference in virtio_gpu_conn_get_modes(CVE-2022-49532)

    ext4: fix race condition between ext4_write and ext4_convert_inline_data(CVE-2022-49414)

    media: pvrusb2: fix array-index-out-of-bounds in pvr2_i2c_core_init(CVE-2022-49478)

    dlm: fix plock invalid read(CVE-2022-49407)

    NFSD: prevent underflow in nfssvc_decode_writeargs().(CVE-2022-49280)

    NFSv4: Don't hold the layoutget locks across multiple RPC calls(CVE-2022-49316)

    firmware: dmi-sysfs: Fix memory leak in dmi_sysfs_register_handle(CVE-2022-49370)

    ARM: hisi: Add missing of_node_put after of_find_compatible_node(CVE-2022-49447)

    scsi: target: tcmu: Fix possible page UAF(CVE-2022-49053)

    drm/plane: Move range check for format_count earlier(CVE-2021-47659)

    tty: fix deadlock caused by calling printk() under tty_port-lock(CVE-2022-49441)

    bpf, arm64: Clear prog-jited_len along prog-jited(CVE-2022-49341)

    RDMA/hfi1: Fix potential integer multiplication overflow errors(CVE-2022-49404)

    scsi: libfc: Fix use after free in fc_exch_abts_resp().(CVE-2022-49114)

    scsi: qla2xxx: Suppress a kernel complaint in qla_create_qpair().(CVE-2022-49155)

    mm: fix unexpected zeroed page mapping with zram swap(CVE-2022-49052)

    net: tipc: fix possible refcount leak in tipc_sk_create()(CVE-2022-49620)

    RDMA/hfi1: Prevent use of lock before it is initialized(CVE-2022-49433)

    memcg: fix soft lockup in the OOM process(CVE-2024-57977)

    block: don't delete queue kobject before its children(CVE-2022-49259)

    exec: Force single empty string when argv is empty(CVE-2022-49264)

    um: Fix out-of-bounds read in LDT setup(CVE-2022-49395)

    cgroup: Use separate src/dst nodes when preloading css_sets for migration(CVE-2022-49647)

    driver: base: fix UAF when driver_attach failed(CVE-2022-49385)

    nbd: don't allow reconnect after disconnect(CVE-2025-21731)

    vrf: use RCU protection in l3mdev_l3_out().(CVE-2025-21791)

    net_sched: sch_sfq: don't allow 1 packet limit(CVE-2024-57996)

    net: let net.core.dev_weight always be non-zero(CVE-2025-21806)

    tty: synclink_gt: Fix null-pointer-dereference in slgt_clean().(CVE-2022-49307)

    virtio_net: fix xdp_rxq_info bug after suspend/resume(CVE-2022-49687)

    be2net: Fix buffer overflow in be_get_module_eeprom(CVE-2022-49581)

    ubi: ubi_create_volume: Fix use-after-free when volume creation failed(CVE-2022-49388)

    ipmr: do not call mr_mfc_uses_dev() for unres entries(CVE-2025-21719)

    ALSA: jack: Access input_dev under mutex(CVE-2022-49538)

    geneve: Fix use-after-free in geneve_find_dev().(CVE-2025-21858)

    rxrpc: Fix listen() setting the bar too high for the prealloc rings(CVE-2022-49450)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1520
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf9bdbb1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.2.19.h1824.eulerosv2r10",
  "kernel-abi-stablelists-4.18.0-147.5.2.19.h1824.eulerosv2r10",
  "kernel-tools-4.18.0-147.5.2.19.h1824.eulerosv2r10",
  "kernel-tools-libs-4.18.0-147.5.2.19.h1824.eulerosv2r10",
  "python3-perf-4.18.0-147.5.2.19.h1824.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
