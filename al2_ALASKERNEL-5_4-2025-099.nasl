#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.4-2025-099.
##

include('compat.inc');

if (description)
{
  script_id(235794);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2021-3744",
    "CVE-2021-3764",
    "CVE-2021-20321",
    "CVE-2021-41864",
    "CVE-2021-47360",
    "CVE-2021-47373",
    "CVE-2021-47375",
    "CVE-2021-47376",
    "CVE-2021-47379",
    "CVE-2021-47383",
    "CVE-2021-47384",
    "CVE-2021-47386",
    "CVE-2021-47387",
    "CVE-2021-47402",
    "CVE-2021-47404",
    "CVE-2021-47459",
    "CVE-2021-47464",
    "CVE-2021-47497"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.4-2025-099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.4.156-83.273. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.4-2025-099 advisory.

    A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

    A flaw was found in the Linux kernel. A memory leak in the ccp-ops crypto driver can allow attackers to
    cause a denial of service. This vulnerability is similar with the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3744)

    A memory leak flaw was found in the Linux kernel's ccp_run_aes_gcm_cmd() function that allows an attacker
    to cause a denial of service. The vulnerability is similar to the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3764)

    An out-of-bounds (OOB) memory write flaw was found in prealloc_elems_and_freelist in kernel/bpf/stackmap.c
    in the bpf in the Linux kernel. In this flaw, the multiplication to calculate the size could lead to an
    integer overflow which could allow a local attacker, with a special user privilege, to gain access to out-
    of-bounds memory leading to a system crash or a leak of internal kernel information. (CVE-2021-41864)

    In the Linux kernel, the following vulnerability has been resolved:

    binder: make sure fd closes complete (CVE-2021-47360)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v3-its: Fix potential VPE leak on error (CVE-2021-47373)

    In the Linux kernel, the following vulnerability has been resolved:

    blktrace: Fix uaf in blk_trace access after removing by sysfs (CVE-2021-47375)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Add oversize check before call kvcalloc() (CVE-2021-47376)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-cgroup: fix UAF by grabbing blkcg lock before destroying blkg pd (CVE-2021-47379)

    In the Linux kernel, the following vulnerability has been resolved:

    tty: Fix out-of-bound vmalloc access in imageblit (CVE-2021-47383)

    In the Linux kernel, the following vulnerability has been resolved:

    hwmon: (w83793) Fix NULL pointer dereference by removing unnecessary structure field (CVE-2021-47384)

    In the Linux kernel, the following vulnerability has been resolved:

    hwmon: (w83791d) Fix NULL pointer dereference by removing unnecessary structure field (CVE-2021-47386)

    In the Linux kernel, the following vulnerability has been resolved:

    cpufreq: schedutil: Use kobject release() method to free sugov_tunables (CVE-2021-47387)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: flower: protect fl_walk() with rcu (CVE-2021-47402)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: betop: fix slab-out-of-bounds Write in betop_probe (CVE-2021-47404)

    In the Linux kernel, the following vulnerability has been resolved:

    can: j1939: j1939_netdev_start(): fix UAF for rx_kref of j1939_priv (CVE-2021-47459)

    In the Linux kernel, the following vulnerability has been resolved:

    audit: fix possible null-pointer dereference in audit_filter_rules (CVE-2021-47464)

    In the Linux kernel, the following vulnerability has been resolved:

    nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells (CVE-2021-47497)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2025-099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20321.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3744.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3764.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41864.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47360.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47373.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47375.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47376.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47379.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47383.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47384.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47386.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47387.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47402.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47404.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47459.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47497.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41864");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-47459");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

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
  var cve_list = make_list("CVE-2021-3744", "CVE-2021-3764", "CVE-2021-20321", "CVE-2021-41864", "CVE-2021-47360", "CVE-2021-47373", "CVE-2021-47375", "CVE-2021-47376", "CVE-2021-47379", "CVE-2021-47383", "CVE-2021-47384", "CVE-2021-47386", "CVE-2021-47387", "CVE-2021-47402", "CVE-2021-47404", "CVE-2021-47459", "CVE-2021-47464", "CVE-2021-47497");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.4-2025-099");
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
    {'reference':'bpftool-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-aarch64-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-x86_64-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.156-83.273.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.156-83.273.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.156-83.273.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'}
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
