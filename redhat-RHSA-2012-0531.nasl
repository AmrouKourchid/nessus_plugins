#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0531. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78922);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2012-0864", "CVE-2012-1569", "CVE-2012-1573");
  script_bugtraq_id(52201, 52667, 52668);
  script_xref(name:"RHSA", value:"2012:0531");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2012:0531)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rhev-hypervisor6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2012:0531 advisory.

    The rhev-hypervisor6 package provides a Red Hat Enterprise Virtualization
    Hypervisor ISO disk image. The Red Hat Enterprise Virtualization Hypervisor
    is a dedicated Kernel-based Virtual Machine (KVM) hypervisor. It includes
    everything necessary to run and manage virtual machines: A subset of the
    Red Hat Enterprise Linux operating environment and the Red Hat Enterprise
    Virtualization Agent.

    Note: Red Hat Enterprise Virtualization Hypervisor is only available for
    the Intel 64 and AMD64 architectures with virtualization extensions.

    A flaw was found in the way libtasn1 decoded DER data. An attacker could
    create carefully-crafted DER encoded input (such as an X.509 certificate)
    that, when parsed by an application that uses libtasn1 (such as
    applications using GnuTLS), could cause the application to crash.
    (CVE-2012-1569)

    A flaw was found in the way GnuTLS decrypted malformed TLS records. This
    could cause a TLS/SSL client or server to crash when processing a
    specially-crafted TLS record from a remote TLS/SSL connection peer.
    (CVE-2012-1573)

    An integer overflow flaw was found in the implementation of the printf
    functions family. This could allow an attacker to bypass FORTIFY_SOURCE
    protections and execute arbitrary code using a format string flaw in an
    application, even though these protections are expected to limit the
    impact of such flaws to an application abort. (CVE-2012-0864)

    Red Hat would like to thank Matthew Hall of Mu Dynamics for reporting
    CVE-2012-1569 and CVE-2012-1573.

    This updated package provides updated components that include fixes for
    various security issues. These issues have no security impact on Red Hat
    Enterprise Virtualization Hypervisor itself, however. The security fixes
    included in this update address the following CVE numbers:

    CVE-2011-4128 (gnutls issue)

    CVE-2012-0879, CVE-2012-1090, and CVE-2012-1097 (kernel issues)

    CVE-2012-0884 and CVE-2012-1165 (openssl issues)

    CVE-2012-0060, CVE-2012-0061, and CVE-2012-0815 (rpm issues)

    This update also fixes the following bug:

    * The Hypervisor previously set the lro_disable option for the enic driver.
    The driver does not support this option, as a result the Hypervisor did
    not correctly detect and configure the network interfaces of a Cisco M81KR
    adaptor, when present. The Hypervisor has been updated and no longer sets
    the invalid option for this driver. (BZ#809463)

    Users of Red Hat Enterprise Virtualization Hypervisor are advised to
    upgrade to this updated package, which fixes these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2012/rhsa-2012_0531.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c816644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:0531");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=794766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=804920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=805432");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rhev-hypervisor6 package based on the guidance in RHSA-2012:0531.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0864");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(190);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6-tools");
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
      {'reference':'rhev-hypervisor6-6.2-20120423.1.el6_2', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'rhev-hypervisor6-tools-6.2-20120423.1.el6_2', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rhev-hypervisor6 / rhev-hypervisor6-tools');
}
