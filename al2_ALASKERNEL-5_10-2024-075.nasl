#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2024-075.
##

include('compat.inc');

if (description)
{
  script_id(213355);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-52447",
    "CVE-2023-52656",
    "CVE-2024-26809",
    "CVE-2024-26816",
    "CVE-2024-26859",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26882",
    "CVE-2024-26891",
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-27025",
    "CVE-2024-27038",
    "CVE-2024-27047",
    "CVE-2024-27065",
    "CVE-2024-27077",
    "CVE-2024-27388",
    "CVE-2024-36031"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2024-075)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.214-202.855. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2024-075 advisory.

    2025-01-21: CVE-2024-26878 was added to this advisory.

    2025-01-21: CVE-2024-27388 was added to this advisory.

    2025-01-21: CVE-2024-26863 was added to this advisory.

    2025-01-21: CVE-2024-27025 was added to this advisory.

    2025-01-21: CVE-2024-26872 was added to this advisory.

    2025-01-21: CVE-2024-26862 was added to this advisory.

    2025-01-21: CVE-2024-26861 was added to this advisory.

    2025-01-21: CVE-2024-27038 was added to this advisory.

    2025-01-21: CVE-2024-26901 was added to this advisory.

    2025-01-21: CVE-2024-26898 was added to this advisory.

    2025-01-21: CVE-2023-52656 was added to this advisory.

    2025-01-21: CVE-2024-26809 was added to this advisory.

    2025-01-21: CVE-2024-26880 was added to this advisory.

    2025-01-21: CVE-2024-26816 was added to this advisory.

    2025-01-21: CVE-2024-26859 was added to this advisory.

    2025-01-21: CVE-2024-36031 was added to this advisory.

    2025-01-21: CVE-2023-52447 was added to this advisory.

    2025-01-21: CVE-2024-27077 was added to this advisory.

    2025-01-21: CVE-2024-27065 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Defer the free of inner map when necessary

    When updating or deleting an inner map in map array or map htab, the mapmay still be accessed by non-
    sleepable program or sleepable program.However bpf_map_fd_put_ptr() decreases the ref-counter of the inner
    mapdirectly through bpf_map_put(), if the ref-counter is the last one(which is true for most cases), the
    inner map will be freed byops->map_free() in a kworker. But for now, most .map_free() callbacksdon't use
    synchronize_rcu() or its variants to wait for the elapse of aRCU grace period, so after the invocation of
    ops->map_free completes,the bpf program which is accessing the inner map may incuruse-after-free problem.

    Fix the free of inner map by invoking bpf_map_free_deferred() after bothone RCU grace period and one tasks
    trace RCU grace period if the innermap has been removed from the outer map before. The deferment
    isaccomplished by using call_rcu() or call_rcu_tasks_trace() whenreleasing the last ref-counter of bpf
    map. The newly-added rcu_headfield in bpf_map shares the same storage space with work field toreduce the
    size of bpf_map. (CVE-2023-52447)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: drop any code related to SCM_RIGHTS (CVE-2023-52656)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_set_pipapo: release elements in clone only from destroy path (CVE-2024-26809)

    In the Linux kernel, the following vulnerability has been resolved:

    x86, relocs: Ignore relocations in .notes section (CVE-2024-26816)

    In the Linux kernel, the following vulnerability has been resolved:

    net/bnx2x: Prevent access to a freed page in page_pool (CVE-2024-26859)

    In the Linux kernel, the following vulnerability has been resolved:

    wireguard: receive: annotate data-race around receiving_counter.counter (CVE-2024-26861)

    In the Linux kernel, the following vulnerability has been resolved:

    packet: annotate data-races around ignore_outgoing (CVE-2024-26862)

    In the Linux kernel, the following vulnerability has been resolved:

    hsr: Fix uninit-value access in hsr_get_node() (CVE-2024-26863)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSv4.2: fix nfs4_listxattr kernel BUG at mm/usercopy.c:102 (CVE-2024-26870)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/srpt: Do not register event handler until srpt device is fully setup (CVE-2024-26872)

    In the Linux kernel, the following vulnerability has been resolved:

    quota: Fix potential NULL pointer dereference (CVE-2024-26878)

    In the Linux kernel, the following vulnerability has been resolved:

    dm: call the resume method on internal suspend (CVE-2024-26880)

    In the Linux kernel, the following vulnerability has been resolved:

    net: ip_tunnel: make sure to pull inner header in ip_tunnel_rcv() (CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Don't issue ATS Invalidation request when device is disconnected (CVE-2024-26891)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved:

    aoe: fix the potential use-after-free problem in aoecmd_cfg_pkts (CVE-2024-26898)

    In the Linux kernel, the following vulnerability has been resolved:

    do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak (CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/mm: Disallow vsyscall page read for copy_from_kernel_nofault() (CVE-2024-26906)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/mlx5: Fix fortify source warning while accessing Eth segment (CVE-2024-26907)

    In the Linux kernel, the following vulnerability has been resolved:

    nbd: null check for nla_nest_start (CVE-2024-27025)

    In the Linux kernel, the following vulnerability has been resolved:

    clk: Fix clk_core_get NULL dereference (CVE-2024-27038)

    In the Linux kernel, the following vulnerability has been resolved:

    net: phy: fix phy_get_internal_delay accessing an empty array (CVE-2024-27047)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: do not compare internal table flags on updates (CVE-2024-27065)

    In the Linux kernel, the following vulnerability has been resolved:

    media: v4l2-mem2mem: fix a memleak in v4l2_m2m_register_entity (CVE-2024-27077)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: fix some memleaks in gssx_dec_option_array (CVE-2024-27388)

    In the Linux kernel, the following vulnerability has been resolved:

    keys: Fix overwrite of key expiration on instantiation (CVE-2024-36031)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2024-075.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52447.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52656.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26859.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26861.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26863.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26870.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26872.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26878.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26880.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26891.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26894.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26901.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26907.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27038.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27047.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27065.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27077.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27388.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36031.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.214-202.855");
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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2023-52447", "CVE-2023-52656", "CVE-2024-26809", "CVE-2024-26816", "CVE-2024-26859", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26863", "CVE-2024-26870", "CVE-2024-26872", "CVE-2024-26878", "CVE-2024-26880", "CVE-2024-26882", "CVE-2024-26891", "CVE-2024-26894", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26906", "CVE-2024-26907", "CVE-2024-27025", "CVE-2024-27038", "CVE-2024-27047", "CVE-2024-27065", "CVE-2024-27077", "CVE-2024-27388", "CVE-2024-36031");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2024-075");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.10"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.214-202.855.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.214-202.855-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.214-202.855-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.214-202.855.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.214-202.855.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
