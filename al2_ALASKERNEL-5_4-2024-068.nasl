#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.4-2024-068.
##

include('compat.inc');

if (description)
{
  script_id(198245);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id(
    "CVE-2023-52504",
    "CVE-2024-0841",
    "CVE-2024-26688",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26751",
    "CVE-2024-26752",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26835",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26848",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27417",
    "CVE-2024-35807"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.4-2024-068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.4.271-184.369. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.4-2024-068 advisory.

    2024-12-05: CVE-2024-26754 was added to this advisory.

    2024-12-05: CVE-2024-27414 was added to this advisory.

    2024-09-12: CVE-2024-35807 was added to this advisory.

    2024-09-12: CVE-2024-27413 was added to this advisory.

    2024-08-27: CVE-2024-26773 was added to this advisory.

    2024-08-27: CVE-2024-26840 was added to this advisory.

    2024-08-27: CVE-2024-26752 was added to this advisory.

    2024-08-27: CVE-2024-26751 was added to this advisory.

    2024-08-27: CVE-2024-26835 was added to this advisory.

    2024-08-27: CVE-2024-26688 was added to this advisory.

    2024-08-27: CVE-2024-26804 was added to this advisory.

    2024-08-27: CVE-2024-26772 was added to this advisory.

    2024-08-27: CVE-2024-26763 was added to this advisory.

    2024-08-27: CVE-2024-26805 was added to this advisory.

    2024-08-27: CVE-2024-26764 was added to this advisory.

    2024-08-27: CVE-2024-26735 was added to this advisory.

    2024-08-27: CVE-2024-26848 was added to this advisory.

    2024-08-27: CVE-2024-26793 was added to this advisory.

    2024-08-27: CVE-2024-26791 was added to this advisory.

    2024-08-27: CVE-2024-26845 was added to this advisory.

    2024-07-03: CVE-2023-52504 was added to this advisory.

    2024-07-03: CVE-2024-0841 was added to this advisory.

    2024-06-06: CVE-2024-27417 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    x86/alternatives: Disable KASAN in apply_alternatives() (CVE-2023-52504)

    A null pointer dereference flaw was found in the hugetlbfs_fill_super function in the Linux kernel
    hugetlbfs (HugeTLB pages) functionality. This issue may allow a local user to crash the system or
    potentially escalate their privileges on the system. (CVE-2024-0841)

    In the Linux kernel, the following vulnerability has been resolved:

    fs,hugetlb: fix NULL pointer dereference in hugetlbs_fill_super (CVE-2024-26688)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved: afs: Increase buffer size in
    afs_update_volume_status() The max length of volume->vid value is 20 characters. So increase idbuf[] size
    up to 24 to avoid overflow. Found by Linux Verification Center (linuxtesting.org) with SVACE. [DH:
    Actually, it's 20 + NUL, so increase it to 24 and use snprintf()] (CVE-2024-26736)

    In the Linux kernel, the following vulnerability has been resolved:

    ARM: ep93xx: Add terminator to gpiod_lookup_table (CVE-2024-26751)

    In the Linux kernel, the following vulnerability has been resolved:

    l2tp: pass correct message length to ip6_append_data (CVE-2024-26752)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: fix use-after-free and null-ptr-deref in gtp_genl_dump_pdp() (CVE-2024-26754)

    In the Linux kernel, the following vulnerability has been resolved:

    dm-crypt: don't modify the data when using authenticated encryption (CVE-2024-26763)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/aio: Restrict kiocb_set_cancel_fn() to I/O submitted via libaio (CVE-2024-26764)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal() (CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found() (CVE-2024-26773)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: dev-replace: properly validate device names (CVE-2024-26791)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: fix use-after-free and null-ptr-deref in gtp_newlink() (CVE-2024-26793)

    In the Linux kernel, the following vulnerability has been resolved:

    net: ip_tunnel: prevent perpetual headroom growth (CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: Fix kernel-infoleak-after-free in __skb_datagram_iter (CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: set dormant flag on hook register failure (CVE-2024-26835)

    In the Linux kernel, the following vulnerability has been resolved:

    cachefiles: fix memory leak in cachefiles_add_cache() (CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Add TMF to tmr_list handling (CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved:

    afs: Fix endless loop in directory parsing (CVE-2024-26848)

    In the Linux kernel, the following vulnerability has been resolved:

    efi/capsule-loader: fix incorrect allocation size (CVE-2024-27413)

    In the Linux kernel, the following vulnerability has been resolved:

    rtnetlink: fix error logic of IFLA_BRIDGE_FLAGS writing back (CVE-2024-27414)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: fix potential struct net leak in inet6_rtm_getaddr() (CVE-2024-27417)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix corruption during on-line resize (CVE-2024-35807)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2024-068.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52504.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26688.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26736.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26751.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26752.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26754.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26764.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26773.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26793.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26848.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27414.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27417.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35807.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-52504", "CVE-2024-0841", "CVE-2024-26688", "CVE-2024-26735", "CVE-2024-26736", "CVE-2024-26751", "CVE-2024-26752", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26835", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26848", "CVE-2024-27413", "CVE-2024-27414", "CVE-2024-27417", "CVE-2024-35807");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.4-2024-068");
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
    {'reference':'bpftool-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-aarch64-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-x86_64-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.271-184.369.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.271-184.369.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.271-184.369.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'}
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
