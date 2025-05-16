#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-695.
##

include('compat.inc');

if (description)
{
  script_id(205098);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-26605",
    "CVE-2024-26924",
    "CVE-2024-26939",
    "CVE-2024-26983",
    "CVE-2024-26987",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26992",
    "CVE-2024-26993",
    "CVE-2024-27000",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27013",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27018",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27022",
    "CVE-2024-27395",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35857",
    "CVE-2024-35995"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-695)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-695 advisory.

    2024-12-05: CVE-2024-27000 was added to this advisory.

    2024-12-05: CVE-2024-26993 was added to this advisory.

    2024-12-05: CVE-2024-26988 was added to this advisory.

    2024-12-05: CVE-2024-26983 was added to this advisory.

    2024-12-05: CVE-2024-27004 was added to this advisory.

    2024-12-05: CVE-2024-27003 was added to this advisory.

    2024-12-05: CVE-2024-27022 was added to this advisory.

    2024-11-13: CVE-2024-35849 was added to this advisory.

    2024-09-12: CVE-2024-35857 was added to this advisory.

    2024-09-12: CVE-2024-35847 was added to this advisory.

    2024-08-14: CVE-2024-35995 was added to this advisory.

    2024-08-14: CVE-2024-26605 was added to this advisory.

    2024-08-14: CVE-2024-27395 was added to this advisory.

    2024-08-14: CVE-2024-26924 was added to this advisory.

    2024-08-14: CVE-2024-26939 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved: PCI/ASPM: Fix deadlock when enabling
    ASPM A last minute revert in 6.7-final introduced a potential deadlock when enabling ASPM during probe of
    Qualcomm PCIe controllers as reported by lockdep (CVE-2024-26605)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_set_pipapo: do not free live element (CVE-2024-26924)

    In the Linux kernel, the following vulnerability has been resolved: drm/i915/vma: Fix UAF on destroy
    against retire race Object debugging tools were sporadically reporting illegal attempts to free a still
    active i915 VMA object when parking a GT believed to be idle. (CVE-2024-26939)

    In the Linux kernel, the following vulnerability has been resolved:

    bootconfig: use memblock_free_late to free xbc memory to buddy (CVE-2024-26983)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/memory-failure: fix deadlock when hugetlb_optimize_vmemmap is enabled (CVE-2024-26987)

    In the Linux kernel, the following vulnerability has been resolved:

    init/main.c: Fix potential static_command_line memory overflow (CVE-2024-26988)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: hibernate: Fix level3 translation fault in swsusp_save() (CVE-2024-26989)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: x86/pmu: Disable support for adaptive PEBS (CVE-2024-26992)

    In the Linux kernel, the following vulnerability has been resolved:

    fs: sysfs: Fix reference leak in sysfs_break_active_protection() (CVE-2024-26993)

    In the Linux kernel, the following vulnerability has been resolved:

    serial: mxs-auart: add spinlock around changing cts state (CVE-2024-27000)

    In the Linux kernel, the following vulnerability has been resolved:

    clk: Get runtime PM before walking tree for clk_summary (CVE-2024-27003)

    In the Linux kernel, the following vulnerability has been resolved:

    clk: Get runtime PM before walking tree during disable_unused (CVE-2024-27004)

    In the Linux kernel, the following vulnerability has been resolved:

    tun: limit printing rate when illegal packet received by tun dev (CVE-2024-27013)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: flowtable: incorrect pppoe tuple (CVE-2024-27015)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: flowtable: validate pppoe header (CVE-2024-27016)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: br_netfilter: skip conntrack input hook for promisc packets (CVE-2024-27018)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (CVE-2024-27019)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (CVE-2024-27020)

    In the Linux kernel, the following vulnerability has been resolved:

    fork: defer linking file vma until vma is fully initialized (CVE-2024-27022)

    In the Linux kernel, the following vulnerability has been resolved:

    net: openvswitch: Fix Use-After-Free in ovs_ct_exit (CVE-2024-27395)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v3-its: Prevent double free on error (CVE-2024-35847)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix information leak in btrfs_ioctl_logical_to_ino() (CVE-2024-35849)

    In the Linux kernel, the following vulnerability has been resolved:

    icmp: prevent possible NULL dereferences from icmp_build_probe() (CVE-2024-35857)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: CPPC: Use access_width over bit_width for system memory accesses (CVE-2024-35995)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-695.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26605.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26924.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26983.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26987.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26988.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26989.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26992.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26993.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27003.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27004.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27018.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27020.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27022.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27395.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35847.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35857.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35995.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.5.20240805' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.90-99.173");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2024-26605", "CVE-2024-26924", "CVE-2024-26939", "CVE-2024-26983", "CVE-2024-26987", "CVE-2024-26988", "CVE-2024-26989", "CVE-2024-26992", "CVE-2024-26993", "CVE-2024-27000", "CVE-2024-27003", "CVE-2024-27004", "CVE-2024-27013", "CVE-2024-27015", "CVE-2024-27016", "CVE-2024-27018", "CVE-2024-27019", "CVE-2024-27020", "CVE-2024-27022", "CVE-2024-27395", "CVE-2024-35847", "CVE-2024-35849", "CVE-2024-35857", "CVE-2024-35995");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-695");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.90-99.173-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.90-99.173-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.90-99.173.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
