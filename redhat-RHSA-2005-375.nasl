#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:375. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18129);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2005-0941");
  script_xref(name:"RHSA", value:"2005:375");

  script_name(english:"RHEL 4 : openoffice.org (RHSA-2005:375)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for openoffice.org.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2005:375 advisory.

    OpenOffice.org is an office productivity suite that includes desktop
    applications such as a word processor, spreadsheet, presentation manager,
    formula editor, and drawing program.

    A heap based buffer overflow bug was found in the OpenOffice.org DOC file
    processor. An attacker could create a carefully crafted DOC file in such a
    way that it could cause OpenOffice.org to execute arbitrary code when the
    file was opened by a victim. The Common Vulnerabilities and Exposures
    project (cve.mitre.org) has assigned the name CAN-2005-0941 to this issue.

    All users of OpenOffice.org are advised to upgrade to these updated
    packages, which contain backported fixes for these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_375.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8672f698");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/issues/show_bug.cgi?id=46388");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=154540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:375");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openoffice.org package based on the guidance in RHSA-2005:375.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0941");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '4')) audit(AUDIT_OS_NOT, 'Red Hat 4.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/as/4/4AS/i386/os',
      'content/dist/rhel/as/4/4AS/i386/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/i386/os',
      'content/dist/rhel/desktop/4/4Desktop/i386/source/SRPMS',
      'content/dist/rhel/es/4/4ES/i386/os',
      'content/dist/rhel/es/4/4ES/i386/source/SRPMS',
      'content/dist/rhel/power/4/4AS/ppc/os',
      'content/dist/rhel/power/4/4AS/ppc/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openoffice.org-1.1.2-24.6.0.EL4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-1.1.2-24.6.0.EL4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-i18n-1.1.2-24.6.0.EL4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-i18n-1.1.2-24.6.0.EL4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-kde-1.1.2-24.6.0.EL4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-kde-1.1.2-24.6.0.EL4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-libs-1.1.2-24.6.0.EL4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openoffice.org-libs-1.1.2-24.6.0.EL4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openoffice.org / openoffice.org-i18n / openoffice.org-kde / etc');
}
