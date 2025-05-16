#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.4-2025-094.
##

include('compat.inc');

if (description)
{
  script_id(216788);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2024-44986",
    "CVE-2024-47707",
    "CVE-2024-49884",
    "CVE-2024-49936",
    "CVE-2024-49960",
    "CVE-2024-50055",
    "CVE-2024-50067",
    "CVE-2024-53124",
    "CVE-2024-53164",
    "CVE-2024-53690",
    "CVE-2024-54031",
    "CVE-2024-55916",
    "CVE-2024-56631",
    "CVE-2024-56658",
    "CVE-2024-57807",
    "CVE-2024-57884",
    "CVE-2024-57890",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57929",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946",
    "CVE-2024-57951",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21653",
    "CVE-2025-21664",
    "CVE-2025-21678",
    "CVE-2025-21687",
    "CVE-2025-21689",
    "CVE-2025-21694",
    "CVE-2025-21699"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.4-2025-094)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.4.290-205.397. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.4-2025-094 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: fix possible UAF in ip6_finish_output2() (CVE-2024-44986)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev() (CVE-2024-47707)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix slab-use-after-free in ext4_split_extent_at() (CVE-2024-49884)

    In the Linux kernel, the following vulnerability has been resolved:

    net/xen-netback: prevent UAF in xenvif_flush_hash() (CVE-2024-49936)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix timer use-after-free on failed mount (CVE-2024-49960)

    In the Linux kernel, the following vulnerability has been resolved:

    driver core: bus: Fix double free in driver API bus_register() (CVE-2024-50055)

    In the Linux kernel, the following vulnerability has been resolved:

    uprobe: avoid out-of-bounds memory access of fetching args (CVE-2024-50067)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix data-races around sk->sk_forward_alloc (CVE-2024-53124)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: fix ordering of qlen adjustment (CVE-2024-53164)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: prevent use of deleted inode (CVE-2024-53690)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_set_hash: unaligned atomic read on struct nft_set_ext (CVE-2024-54031)

    In the Linux kernel, the following vulnerability has been resolved:

    Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet (CVE-2024-55916)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: sg: Fix slab-use-after-free read in sg_release() (CVE-2024-56631)

    In the Linux kernel, the following vulnerability has been resolved:

    net: defer final 'struct net' free in netns dismantle (CVE-2024-56658)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: megaraid_sas: Fix for a potential deadlock (CVE-2024-57807)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim() (CVE-2024-57884)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/uverbs: Prevent integer overflow issue (CVE-2024-57890)

    In the Linux kernel, the following vulnerability has been resolved:

    ila: serialize calls to nf_register_net_hooks() (CVE-2024-57900)

    In the Linux kernel, the following vulnerability has been resolved:

    af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK (CVE-2024-57901)

    In the Linux kernel, the following vulnerability has been resolved:

    af_packet: fix vlan_get_tci() vs MSG_PEEK (CVE-2024-57902)

    In the Linux kernel, the following vulnerability has been resolved:

    dm array: fix releasing a faulty array block twice in dm_array_cursor_end (CVE-2024-57929)

    In the Linux kernel, the following vulnerability has been resolved:

    selinux: ignore unknown extended permissions (CVE-2024-57931)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sctp: Prevent autoclose integer overflow in sctp_association_init() (CVE-2024-57938)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio-blk: don't keep queue frozen during system suspend (CVE-2024-57946)

    In the Linux kernel, the following vulnerability has been resolved:

    hrtimers: Handle CPU state correctly on hotplug (CVE-2024-57951)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: sysctl: auth_enable: avoid using current->nsproxy (CVE-2025-21638)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: sysctl: rto_min/max: avoid using current->nsproxy (CVE-2025-21639)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy (CVE-2025-21640)

    In the Linux kernel, the following vulnerability has been resolved:

    net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute (CVE-2025-21653)

    In the Linux kernel, the following vulnerability has been resolved:

    dm thin: make get_first_thin use rcu-safe list first function (CVE-2025-21664)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: Destroy device along with udp socket's netns dismantle. (CVE-2025-21678)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/platform: check the bounds of read/write syscalls (CVE-2025-21687)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: serial: quatech2: fix null-ptr-deref in qt2_process_read_urb() (CVE-2025-21689)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/proc: fix softlockup in __read_vmcore (part 2) (CVE-2025-21694)

    In the Linux kernel, the following vulnerability has been resolved:

    gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag (CVE-2025-21699)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2025-094.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-44986.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47707.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49884.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49936.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50067.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53164.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53690.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-54031.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-55916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56631.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-56658.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57807.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57884.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57890.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57900.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57901.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57902.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21638.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21639.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21640.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21653.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21664.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21678.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21687.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21689.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21694.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-21699.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
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
  var cve_list = make_list("CVE-2024-44986", "CVE-2024-47707", "CVE-2024-49884", "CVE-2024-49936", "CVE-2024-49960", "CVE-2024-50055", "CVE-2024-50067", "CVE-2024-53124", "CVE-2024-53164", "CVE-2024-53690", "CVE-2024-54031", "CVE-2024-55916", "CVE-2024-56631", "CVE-2024-56658", "CVE-2024-57807", "CVE-2024-57884", "CVE-2024-57890", "CVE-2024-57900", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57929", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57946", "CVE-2024-57951", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21653", "CVE-2025-21664", "CVE-2025-21678", "CVE-2025-21687", "CVE-2025-21689", "CVE-2025-21694", "CVE-2025-21699");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.4-2025-094");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.4"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-aarch64-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-x86_64-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.290-205.397.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.290-205.397.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.290-205.397.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'}
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
