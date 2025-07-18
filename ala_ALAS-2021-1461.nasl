##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1461.
##

include('compat.inc');

if (description)
{
  script_id(145005);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2019-19770",
    "CVE-2020-8694",
    "CVE-2020-14351",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-28941",
    "CVE-2020-28974"
  );
  script_xref(name:"ALAS", value:"2021-1461");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2021-1461)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.209-117.337. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2021-1461 advisory.

    A use-after-free flaw was found in the debugfs_remove function in the Linux kernel. The flaw could allow a
    local attacker with special user (or root) privilege to crash the system at the time of file or directory
    removal. This vulnerability can lead to a kernel information leak. The highest threat from this
    vulnerability is to system availability. (CVE-2019-19770)

    A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges.  The highest threat from this vulnerability is to data confidentiality and integrity as well
    as system availability. (CVE-2020-14351)

    A flaw was found in the Linux kernel. A use-after-free was found in the way the console subsystem was
    using ioctls KDGKBSENT and KDSKBSENT. A local user could use this flaw to get read memory access out of
    bounds. The highest threat from this vulnerability is to data confidentiality. (CVE-2020-25656)

    A flaw was found in Linux Kernel because access to the global variable fg_console is not properly
    synchronized leading to a use after free in con_font_op. (CVE-2020-25668)

    The function sunkbd_reinit having been scheduled by sunkbd_interrupt before sunkbd being freed.Though the
    dangling pointer is set to NULL in sunkbd_disconnect, there is still a alias in sunkbd_reinit so that
    causing Use After Free. (CVE-2020-25669)

    A flaw memory leak in the Linux kernel performance monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this flaw to starve the resources causing denial of
    service. (CVE-2020-25704)

    An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x. Guest OS users
    can cause a denial of service (host OS hang) via a high rate of events to dom0, aka CID-e99502f76271.
    (CVE-2020-27673)

    An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x.
    drivers/xen/events/events_base.c allows event-channel removal during the event-handling loop (a race
    condition). This can cause a use-after-free or NULL pointer dereference, as demonstrated by a dom0 crash
    via events for an in-reconfiguration paravirtualized device, aka CID-073d0552ead5. (CVE-2020-27675)

    A flaw was found in the way RTAS handled memory accesses in userspace to kernel communication. On a locked
    down (usually due to Secure Boot) guest system running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to further increase their privileges to that of a
    running kernel. (CVE-2020-27777)

    An issue was discovered in drivers/accessibility/speakup/spk_ttyio.c in the Linux kernel through 5.9.9.
    Local attackers on systems with the speakup driver could cause a local denial of service attack, aka
    CID-d41227544427. This occurs because of an invalid free when the line discipline is used more than once.
    (CVE-2020-28941)

    An out-of-bounds (OOB) SLAB memory access flaw was found in the Linux kernel's fbcon driver module. A
    bounds check failure allows a local attacker with special user privileges to gain access to out-of-bounds
    memory, leading to a system crash or leaking of internal kernel information. The highest threat from this
    vulnerability is to system availability. (CVE-2020-28974)

    A flaw was found in the Linux kernel's implementation of Intel's Running Average Power Limit (RAPL)
    implementation. A local attacker could infer secrets by measuring power usage and also infer private data
    by observing the power usage of calculations performed on the data. (CVE-2020-8694)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1461.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27675");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27777");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28941");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8694");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kpatch.nasl", "ssh_get_info.nasl");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2019-19770", "CVE-2020-8694", "CVE-2020-14351", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-28941", "CVE-2020-28974");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2021-1461");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-i686-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.209-117.337.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.209-117.337.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
