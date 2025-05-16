#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1026. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78964);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2013-1773",
    "CVE-2013-1796",
    "CVE-2013-1797",
    "CVE-2013-1798",
    "CVE-2013-1848"
  );
  script_bugtraq_id(
    58200,
    58600,
    58604,
    58605,
    58607
  );
  script_xref(name:"RHSA", value:"2013:1026");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:1026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2013:1026 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    This update fixes the following security issues:

    * A buffer overflow flaw was found in the way UTF-8 characters were
    converted to UTF-16 in the utf8s_to_utf16s() function of the Linux kernel's
    FAT file system implementation. A local user able to mount a FAT file
    system with the utf8=1 option could use this flaw to crash the system or,
    potentially, to escalate their privileges. (CVE-2013-1773, Important)

    * A flaw was found in the way KVM (Kernel-based Virtual Machine) handled
    guest time updates when the buffer the guest registered by writing to the
    MSR_KVM_SYSTEM_TIME machine state register (MSR) crossed a page boundary. A
    privileged guest user could use this flaw to crash the host or,
    potentially, escalate their privileges, allowing them to execute arbitrary
    code at the host kernel level. (CVE-2013-1796, Important)

    * A potential use-after-free flaw was found in the way KVM handled guest
    time updates when the GPA (guest physical address) the guest registered by
    writing to the MSR_KVM_SYSTEM_TIME machine state register (MSR) fell into a
    movable or removable memory region of the hosting user-space process (by
    default, QEMU-KVM) on the host. If that memory region is deregistered from
    KVM using KVM_SET_USER_MEMORY_REGION and the allocated virtual memory
    reused, a privileged guest user could potentially use this flaw to escalate
    their privileges on the host. (CVE-2013-1797, Important)

    * A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
    Programmable Interrupt Controller). A missing validation check in the
    ioapic_read_indirect() function could allow a privileged guest user to
    crash the host, or read a substantial portion of host kernel memory.
    (CVE-2013-1798, Important)

    * A format string flaw was found in the ext3_msg() function in the Linux
    kernel's ext3 file system implementation. A local user who is able to mount
    an ext3 file system could use this flaw to cause a denial of service or,
    potentially, escalate their privileges. (CVE-2013-1848, Low)

    Red Hat would like to thank Andrew Honig of Google for reporting
    CVE-2013-1796, CVE-2013-1797, and CVE-2013-1798.

    This update also fixes several bugs. Documentation for these changes will
    be available shortly from the Technical Notes document linked to in the
    References section.

    Users should upgrade to these updated packages, which contain backported
    patches to correct these issues. The system must be rebooted for this
    update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/6.2_Technical_Notes/kernel.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63a76eaf");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_1026.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97307da7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1026");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=916115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=917012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=917013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=917017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=920783");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2013:1026.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1797");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-1798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '6.2')) audit(AUDIT_OS_NOT, 'Red Hat 6.2', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2013-1773', 'CVE-2013-1796', 'CVE-2013-1797', 'CVE-2013-1798', 'CVE-2013-1848');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2013:1026');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.2/x86_64/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/os',
      'content/aus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.2/x86_64/os',
      'content/aus/rhel/server/6/6.2/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.2/ppc64/debug',
      'content/eus/rhel/power/6/6.2/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.2/ppc64/optional/os',
      'content/eus/rhel/power/6/6.2/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.2/ppc64/os',
      'content/eus/rhel/power/6/6.2/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/debug',
      'content/eus/rhel/server/6/6.2/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.2/i386/highavailability/os',
      'content/eus/rhel/server/6/6.2/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/optional/debug',
      'content/eus/rhel/server/6/6.2/i386/optional/os',
      'content/eus/rhel/server/6/6.2/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/os',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/debug',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.2/x86_64/optional/os',
      'content/eus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/os',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.2/s390x/debug',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.2/s390x/os',
      'content/eus/rhel/system-z/6/6.2/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-firmware-2.6.32-220.39.1.el6', 'sp':'2', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-220.39.1.el6', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-bootwrapper / kernel-debug / kernel-debug-devel / etc');
}
