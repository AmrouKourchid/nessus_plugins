#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2024-047.
##

include('compat.inc');

if (description)
{
  script_id(205709);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2023-52884",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-35927",
    "CVE-2024-36016",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36489",
    "CVE-2024-36971",
    "CVE-2024-36972",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38555",
    "CVE-2024-38573",
    "CVE-2024-38598",
    "CVE-2024-38612",
    "CVE-2024-38623",
    "CVE-2024-38624",
    "CVE-2024-38662"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2024-047)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.161-106.159. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2024-047 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    Input: cyapa - add missing input core locking to suspend/resume functions (CVE-2023-52884)

    In the Linux kernel, the following vulnerability has been resolved:

    genirq/cpuhotplug, x86/vector: Prevent vector leak during CPU offline (CVE-2024-31076)

    In the Linux kernel, the following vulnerability has been resolved:

    ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound (CVE-2024-33621)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Check output polling initialized before disabling (CVE-2024-35927)

    In the Linux kernel, the following vulnerability has been resolved:

    tty: n_gsm: fix possible out-of-bounds in gsm0_receive() (CVE-2024-36016)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: tproxy: bail out if IP has been disabled on the device (CVE-2024-36270)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu() (CVE-2024-36286)

    In the Linux kernel, the following vulnerability has been resolved:

    tls: fix missing memory barrier in tls_init (CVE-2024-36489)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix __dst_negative_advice() race (CVE-2024-36971)

    In the Linux kernel, the following vulnerability has been resolved:

    af_unix: Update unix_sk(sk)->oob_skb under sk_receive_queue lock. (CVE-2024-36972)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio: delete vq in vp_find_vqs_msix() when request_irq() fails (CVE-2024-37353)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: Fix shift-out-of-bounds in dctcp_update_alpha(). (CVE-2024-37356)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: Discard command completions in internal error (CVE-2024-38555)

    In the Linux kernel, the following vulnerability has been resolved:

    cppc_cpufreq: Fix possible null pointer dereference (CVE-2024-38573)

    In the Linux kernel, the following vulnerability has been resolved:

    md: fix resync softlockup when bitmap size is less than array size (CVE-2024-38598)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix invalid unregister error path (CVE-2024-38612)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Use variable length array instead of fixed size (CVE-2024-38623)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Use 64 bit variable to avoid 32 bit overflow (CVE-2024-38624)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Allow delete from sockmap/sockhash only if update is allowed (CVE-2024-38662)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2024-047.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52884.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-31076.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-33621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36270.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36489.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36971.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36972.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-37353.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-37356.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38555.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38573.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38662.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.161-106.159");
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
  var cve_list = make_list("CVE-2023-52884", "CVE-2024-31076", "CVE-2024-33621", "CVE-2024-35927", "CVE-2024-36016", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36489", "CVE-2024-36971", "CVE-2024-36972", "CVE-2024-37353", "CVE-2024-37356", "CVE-2024-38555", "CVE-2024-38573", "CVE-2024-38598", "CVE-2024-38612", "CVE-2024-38623", "CVE-2024-38624", "CVE-2024-38662");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2024-047");
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
    {'reference':'bpftool-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.161-106.159.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.161-106.159-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.161-106.159-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.161-106.159.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.161-106.159.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
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
