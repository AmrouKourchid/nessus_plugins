#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0434. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210146);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2009-0788", "CVE-2010-1171");
  script_xref(name:"RHSA", value:"2011:0434");

  script_name(english:"RHEL 5 : security update for Red Hat Network Satellite (Moderate) (RHSA-2011:0434)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:0434 advisory.

    Red Hat Network Satellite (RHN Satellite) is a system management tool for
    Linux-based infrastructures. It allows for the provisioning, remote
    management and monitoring of multiple Linux deployments with a single,
    centralized tool.

    RHN Satellite incorrectly exposed an obsolete XML-RPC API for configuring
    package group (comps.xml) files for channels. An authenticated user could
    use this flaw to gain access to arbitrary files accessible to the RHN
    Satellite server process, and prevent clients from performing certain yum
    operations. (CVE-2010-1171)

    A flaw was found in the way RHN Satellite rewrote certain URLs. An
    unauthenticated user could use a specially-crafted HTTP request to obtain
    sensitive information about the host system RHN Satellite was running on.
    They could also use RHN Satellite as a distributed denial of service tool,
    forcing it to connect to an arbitrary service at an arbitrary IP address
    via a specially-crafted HTTP request. (CVE-2009-0788)

    Note: Refer to the Solution section below for manual steps that may be
    required to fully address the CVE-2009-0788 issue.

    Users of RHN Satellite 5.3 and 5.4 are advised to upgrade to these updated
    packages, which contain backported patches to correct these issues. The RHN
    Satellite server must be restarted (rhn-satellite restart) for this
    update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=584118");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2011/rhsa-2011_0434.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e67829e6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0434");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-upload-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-config");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/satellite/5.3/os',
      'content/dist/rhel/server/5/5Server/i386/satellite/5.3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.3/os',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.3/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.3/os',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'spacewalk-backend-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-app-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-applet-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-common-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-tool-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-export-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-package-push-server-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-server-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-tools-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-upload-server-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xml-export-libs-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xmlrpc-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xp-0.5.28-59.2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-config-0.5.9-16.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/satellite/5.4/os',
      'content/dist/rhel/server/5/5Server/i386/satellite/5.4/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.4/os',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.4/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.4/os',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'spacewalk-backend-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-app-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-applet-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-common-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-tool-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-export-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-libs-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-package-push-server-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-server-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-oracle-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-tools-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-upload-server-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xml-export-libs-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xmlrpc-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xp-1.2.13-37.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-config-1.2.2-2.el5sat', 'release':'5', 'el_string':'el5sat', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spacewalk-backend / spacewalk-backend-app / etc');
}
