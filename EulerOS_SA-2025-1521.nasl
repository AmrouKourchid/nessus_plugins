#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235756);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2022-49052",
    "CVE-2022-49053",
    "CVE-2022-49114",
    "CVE-2022-49308",
    "CVE-2022-49341",
    "CVE-2022-49414",
    "CVE-2022-49447",
    "CVE-2022-49526",
    "CVE-2022-49720",
    "CVE-2023-52572",
    "CVE-2024-53124",
    "CVE-2024-53173",
    "CVE-2024-53217",
    "CVE-2024-56606",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56780",
    "CVE-2024-57883",
    "CVE-2025-21648",
    "CVE-2025-21687",
    "CVE-2025-21731"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2025-1521)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    cifs: Fix UAF in cifs_demultiplex_thread().(CVE-2023-52572)

    net: fix data-races around sk-sk_forward_alloc(CVE-2024-53124)

    quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

    af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

    net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

    netfilter: x_tables: fix LED ID check in led_tg_check().(CVE-2024-56650)

    mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

    NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

    NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

    netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

    vfio/platform: check the bounds of read/write syscalls(CVE-2025-21687)

    mm: fix unexpected zeroed page mapping with zram swap(CVE-2022-49052)

    ext4: fix race condition between ext4_write and ext4_convert_inline_data(CVE-2022-49414)

    block: Fix handling of offline queues in blk_mq_alloc_request_hctx().(CVE-2022-49720)

    scsi: libfc: Fix use after free in fc_exch_abts_resp().(CVE-2022-49114)

    nbd: don't allow reconnect after disconnect(CVE-2025-21731)

    md/bitmap: don't set sb values if can't pass sanity check(CVE-2022-49526)

    ARM: hisi: Add missing of_node_put after of_find_compatible_node(CVE-2022-49447)

    bpf, arm64: Clear prog-jited_len along prog-jited(CVE-2022-49341)

    extcon: Modify extcon device to be created after driver data is set(CVE-2022-49308)

    scsi: target: tcmu: Fix possible page UAF(CVE-2022-49053)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1521
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a65a6cd");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2211.3.0.h2003.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2211.3.0.h2003.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2211.3.0.h2003.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2211.3.0.h2003.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2211.3.0.h2003.eulerosv2r10"
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
