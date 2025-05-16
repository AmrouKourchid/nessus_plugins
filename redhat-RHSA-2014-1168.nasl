#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1168. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79048);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3535");
  script_bugtraq_id(67357, 67391);
  script_xref(name:"RHSA", value:"2014:1168");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2014:1168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rhev-hypervisor6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2014:1168 advisory.

    The rhev-hypervisor6 package provides a Red Hat Enterprise Virtualization
    Hypervisor ISO disk image. The Red Hat Enterprise Virtualization Hypervisor
    is a dedicated Kernel-based Virtual Machine (KVM) hypervisor. It includes
    everything necessary to run and manage virtual machines: a subset of the
    Red Hat Enterprise Linux operating environment and the Red Hat Enterprise
    Virtualization Agent.

    Note: Red Hat Enterprise Virtualization Hypervisor is only available for
    the Intel 64 and AMD64 architectures with virtualization extensions.

    A NULL pointer dereference flaw was found in the way the Linux kernel's
    networking implementation handled logging while processing certain invalid
    packets coming in via a VxLAN interface. A remote attacker could use this
    flaw to crash the system by sending a specially crafted packet to such an
    interface. (CVE-2014-3535)

    Two integer overflow flaws were found in the QEMU block driver for QCOW
    version 1 disk images. A user able to alter the QEMU disk image files
    loaded by a guest could use either of these flaws to corrupt QEMU process
    memory on the host, which could potentially result in arbitrary code
    execution on the host with the privileges of the QEMU process.
    (CVE-2014-0222, CVE-2014-0223)

    Red Hat would like to thank NSA for reporting CVE-2014-0222 and
    CVE-2014-0223.

    This update also fixes the following bug:

    * Previously, an updated version of Qlogic firmware was not supported in
    the Red Hat Enterprise Virtualization Hypervisor 6.5 image and an error
    message returned when users were using a newer version of Qlogic firmware.
    This update includes the latest Qlogic firmware package in the Red Hat
    Enterprise Virtualization Hypervisor 6.5 image so no firmware errors are
    returned. (BZ#1135780)

    This updated package also provides updated components that include fixes
    for various security issues. These issues have no security impact on Red
    Hat Enterprise Virtualization Hypervisor itself, however. The security
    fixes included in this update address the following CVE numbers:

    CVE-2012-6647, CVE-2013-7339, CVE-2014-2672, CVE-2014-2678, CVE-2014-2706,
    CVE-2014-2851, CVE-2014-3144, CVE-2014-3145, CVE-2014-0205, CVE-2014-3917,
    and CVE-2014-4667 (kernel issues)

    Users of the Red Hat Enterprise Virtualization Hypervisor are advised to
    upgrade to this updated package.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2014/rhsa-2014_1168.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a22bf0b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1168");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1097216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1097222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1114540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1127635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1135780");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rhev-hypervisor6 package based on the guidance in RHSA-2014:1168.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/debug',
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/os',
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/debug',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/os',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rhev-hypervisor6-6.5-20140821.1.el6ev', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rhev-hypervisor6');
}
