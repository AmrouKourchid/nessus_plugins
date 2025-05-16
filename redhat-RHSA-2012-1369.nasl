#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1369. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78937);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2012-2679");
  script_bugtraq_id(55934);
  script_xref(name:"RHSA", value:"2012:1369");

  script_name(english:"RHEL 5 / 6 : rhncfg (RHSA-2012:1369)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2012:1369 advisory.

    Red Hat Network Tools provide programs and libraries that allow your system
    to use provisioning, monitoring, and configuration management capabilities
    provided by Red Hat Network and Red Hat Network Satellite.

    It was discovered that the Red Hat Network (RHN) Configuration Client
    (rhncfg-client) tool set world-readable permissions on the
    /var/log/rhncfg-actions file, used to store the output of different
    rhncfg-client actions (such as diffing and verifying files). This could
    possibly allow a local attacker to obtain sensitive information they would
    otherwise not have access to. (CVE-2012-2679)

    Note: With this update, rhncfg-client cannot create diffs of files that
    are not already world-readable, and /var/log/rhncfg-actions can only be
    read and written to by the root user.

    This issue was discovered by Paul Wouters of Red Hat.

    This update also fixes the following bugs:

    * When the user attempted to use the rhncfg-client get command to
    download a backup of deployed configuration files and these configuration
    files contained a broken symbolic link, the command failed with an error.
    This update ensures that rhncfg-client get no longer fails in this
    scenario. (BZ#836445)

    * The SYNOPSIS section of the rhn-actions-control(8) manual page has been
    updated to include the --report command line option as expected.
    (BZ#820517)

    As well, this update adds the following enhancement:

    * The rhncfg-manager utility now supports a new command line option,
    --selinux-context. This option can be used to upload files and
    directories without setting the Security-Enhanced Linux (SELinux) context.
    (BZ#770575)

    All users of Red Hat Network Tools are advised to upgrade to these updated
    packages, which correct these issues and add this enhancement.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2012/rhsa-2012_1369.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a54d32a8");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:1369");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=820517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=825275");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhncfg-management");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/i386/rhn-tools/os',
      'content/dist/rhel/client/5/5Client/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/rhn-tools/os',
      'content/dist/rhel/client/5/5Client/x86_64/rhn-tools/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/rhn-tools/os',
      'content/dist/rhel/power/5/5Server/ppc/rhn-tools/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/rhn-tools/os',
      'content/dist/rhel/server/5/5Server/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/server/5/5Server/ia64/rhn-tools/os',
      'content/dist/rhel/server/5/5Server/ia64/rhn-tools/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/rhn-tools/os',
      'content/dist/rhel/server/5/5Server/x86_64/rhn-tools/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/rhn-tools/os',
      'content/dist/rhel/system-z/5/5Server/s390x/rhn-tools/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/rhn-tools/os',
      'content/dist/rhel/workstation/5/5Client/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/rhn-tools/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/rhn-tools/source/SRPMS',
      'content/els/rhel/server/5/5Server/i386/rhn-tools/debug',
      'content/els/rhel/server/5/5Server/i386/rhn-tools/os',
      'content/els/rhel/server/5/5Server/i386/rhn-tools/source/SRPMS',
      'content/els/rhel/server/5/5Server/x86_64/rhn-tools/debug',
      'content/els/rhel/server/5/5Server/x86_64/rhn-tools/os',
      'content/els/rhel/server/5/5Server/x86_64/rhn-tools/source/SRPMS',
      'content/els/rhel/system-z/5/5Server/s390x/rhn-tools/debug',
      'content/els/rhel/system-z/5/5Server/s390x/rhn-tools/os',
      'content/els/rhel/system-z/5/5Server/s390x/rhn-tools/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rhncfg-5.10.27-8.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-actions-5.10.27-8.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-client-5.10.27-8.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-management-5.10.27-8.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/rhn-tools/debug',
      'content/dist/rhel/client/6/6Client/i386/rhn-tools/os',
      'content/dist/rhel/client/6/6Client/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/rhn-tools/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhn-tools/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhn-tools/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/rhn-tools/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/rhn-tools/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/rhn-tools/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/rhn-tools/debug',
      'content/dist/rhel/power/6/6Server/ppc64/rhn-tools/os',
      'content/dist/rhel/power/6/6Server/ppc64/rhn-tools/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/rhn-tools/debug',
      'content/dist/rhel/server/6/6Server/i386/rhn-tools/os',
      'content/dist/rhel/server/6/6Server/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhn-tools/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhn-tools/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhn-tools/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/rhn-tools/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/rhn-tools/os',
      'content/dist/rhel/system-z/6/6Server/s390x/rhn-tools/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhn-tools/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhn-tools/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhn-tools/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhn-tools/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhn-tools/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhn-tools/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rhncfg-5.10.27-8.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-actions-5.10.27-8.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-client-5.10.27-8.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhncfg-management-5.10.27-8.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rhncfg / rhncfg-actions / rhncfg-client / rhncfg-management');
}
