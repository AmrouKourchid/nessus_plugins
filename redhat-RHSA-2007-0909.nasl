#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0909. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26952);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2007-0242",
    "CVE-2007-0537",
    "CVE-2007-1308",
    "CVE-2007-1564",
    "CVE-2007-3820",
    "CVE-2007-4224"
  );
  script_xref(name:"RHSA", value:"2007:0909");

  script_name(english:"RHEL 4 / 5 : kdelibs (RHSA-2007:0909)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kdelibs.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 / 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2007:0909 advisory.

    The kdelibs package provides libraries for the K Desktop Environment (KDE).

    Two cross-site-scripting flaws were found in the way Konqueror processes
    certain HTML content. This could result in a malicious attacker presenting
    misleading content to an unsuspecting user. (CVE-2007-0242, CVE-2007-0537)

    A flaw was found in KDE JavaScript implementation.  A web page containing
    malicious JavaScript code could cause Konqueror to crash. (CVE-2007-1308)

    A flaw was found in the way Konqueror handled certain FTP PASV commands.
    A malicious FTP server could use this flaw to perform a rudimentary
    port-scan of machines behind a user's firewall. (CVE-2007-1564)

    Two Konqueror address spoofing flaws have been discovered. It was
    possible for a malicious website to cause the Konqueror address bar to
    display information which could trick a user into believing they are at a
    different website than they actually are. (CVE-2007-3820, CVE-2007-4224)

    Users of KDE should upgrade to these updated packages, which contain
    backported patches to correct these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2007/rhsa-2007_0909.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d3ce7ea");
  script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=229606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=233592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=234633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=248537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=251708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=299891");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2007:0909");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kdelibs package based on the guidance in RHSA-2007:0909.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1564");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2007-0537");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['4','5'])) audit(AUDIT_OS_NOT, 'Red Hat 4.x / 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/as/4/4AS/i386/os',
      'content/dist/rhel/as/4/4AS/i386/source/SRPMS',
      'content/dist/rhel/as/4/4AS/x86_64/os',
      'content/dist/rhel/as/4/4AS/x86_64/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/i386/os',
      'content/dist/rhel/desktop/4/4Desktop/i386/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/os',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/source/SRPMS',
      'content/dist/rhel/es/4/4ES/i386/os',
      'content/dist/rhel/es/4/4ES/i386/source/SRPMS',
      'content/dist/rhel/es/4/4ES/x86_64/os',
      'content/dist/rhel/es/4/4ES/x86_64/source/SRPMS',
      'content/dist/rhel/power/4/4AS/ppc/os',
      'content/dist/rhel/power/4/4AS/ppc/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390/os',
      'content/dist/rhel/system-z/4/4AS/s390/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390x/os',
      'content/dist/rhel/system-z/4/4AS/s390x/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/x86_64/os',
      'content/dist/rhel/ws/4/4WS/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.3.1-9.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.3.1-9.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.3.1-9.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.3.1-9.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.3.1-9.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.3.1-9.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/i386/debug',
      'content/dist/rhel/client/5/5Client/i386/os',
      'content/dist/rhel/client/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/debug',
      'content/dist/rhel/client/5/5Client/x86_64/os',
      'content/dist/rhel/client/5/5Client/x86_64/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/debug',
      'content/dist/rhel/power/5/5Server/ppc/os',
      'content/dist/rhel/power/5/5Server/ppc/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/debug',
      'content/dist/rhel/server/5/5Server/i386/os',
      'content/dist/rhel/server/5/5Server/i386/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/debug',
      'content/dist/rhel/server/5/5Server/x86_64/os',
      'content/dist/rhel/server/5/5Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/debug',
      'content/dist/rhel/system-z/5/5Server/s390x/os',
      'content/dist/rhel/system-z/5/5Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/os',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/os',
      'content/dist/rhel/workstation/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/5/i386/debug',
      'content/fastrack/rhel/client/5/i386/os',
      'content/fastrack/rhel/client/5/i386/source/SRPMS',
      'content/fastrack/rhel/client/5/x86_64/debug',
      'content/fastrack/rhel/client/5/x86_64/os',
      'content/fastrack/rhel/client/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/5/ppc/debug',
      'content/fastrack/rhel/power/5/ppc/os',
      'content/fastrack/rhel/power/5/ppc/source/SRPMS',
      'content/fastrack/rhel/server/5/i386/debug',
      'content/fastrack/rhel/server/5/i386/os',
      'content/fastrack/rhel/server/5/i386/source/SRPMS',
      'content/fastrack/rhel/server/5/x86_64/debug',
      'content/fastrack/rhel/server/5/x86_64/os',
      'content/fastrack/rhel/server/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/5/s390x/debug',
      'content/fastrack/rhel/system-z/5/s390x/os',
      'content/fastrack/rhel/system-z/5/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/os',
      'content/fastrack/rhel/workstation/5/i386/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/os',
      'content/fastrack/rhel/workstation/5/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/os',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/os',
      'content/fastrack/rhel/workstation/5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-3.5.4-13.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-apidocs-3.5.4-13.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-apidocs-3.5.4-13.el5', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-apidocs-3.5.4-13.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-apidocs-3.5.4-13.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
      {'reference':'kdelibs-devel-3.5.4-13.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kdelibs / kdelibs-apidocs / kdelibs-devel');
}
