#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:386. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18148);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2005-0989",
    "CVE-2005-1153",
    "CVE-2005-1154",
    "CVE-2005-1155",
    "CVE-2005-1156",
    "CVE-2005-1157",
    "CVE-2005-1159",
    "CVE-2005-1160"
  );
  script_xref(name:"RHSA", value:"2005:386");

  script_name(english:"RHEL 4 : Mozilla (RHSA-2005:386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Mozilla.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2005:386 advisory.

    Mozilla is an open source Web browser, advanced email and newsgroup client,
    IRC chat client, and HTML editor.

    Vladimir V. Perepelitsa discovered a bug in the way Mozilla handles
    anonymous functions during regular expression string replacement. It is
    possible for a malicious web page to capture a random block of browser
    memory. The Common Vulnerabilities and Exposures project (cve.mitre.org)
    has assigned the name CAN-2005-0989 to this issue.

    Doron Rosenberg discovered a bug in the way Mozilla displays pop-up
    windows. If a user choses to open a pop-up window whose URL is malicious
    javascript, the script will be executed with elevated privileges.
    (CAN-2005-1153)

    A bug was found in the way Mozilla handles the javascript global scope for
    a window. It is possible for a malicious web page to define a global
    variable known to be used by a different site, allowing malicious code to
    be executed in the context of the site. (CAN-2005-1154)

    Michael Krax discovered a bug in the way Mozilla handles favicon links. A
    malicious web page can programatically define a favicon link tag as
    javascript, executing arbitrary javascript with elevated privileges.
    (CAN-2005-1155)

    Michael Krax discovered a bug in the way Mozilla installed search plugins.
    If a user chooses to install a search plugin from a malicious site, the new
    plugin could silently overwrite an existing plugin. This could allow the
    malicious plugin to execute arbitrary code and stealm sensitive
    information. (CAN-2005-1156 CAN-2005-1157)

    A bug was found in the way Mozilla validated several XPInstall related
    javascript objects. A malicious web page could pass other objects to the
    XPInstall objects, resulting in the javascript interpreter jumping to
    arbitrary locations in memory. (CAN-2005-1159)

    A bug was found in the way the Mozilla privileged UI code handled DOM nodes
    from the content window. A malicious web page could install malicious
    javascript code or steal data requiring a user to do commonplace actions
    such as clicking a link or opening the context menu. (CAN-2005-1160)

    Users of Mozilla are advised to upgrade to this updated package which
    contains Mozilla version 1.7.7 to correct these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_386.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7187bb1e");
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f0c0794");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=155116");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:386");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Mozilla package based on the guidance in RHSA-2005:386.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-1159");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
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
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/x86_64/os',
      'content/dist/rhel/ws/4/4WS/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'devhelp-0.9.2-2.4.4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devhelp-0.9.2-2.4.4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devhelp-0.9.2-2.4.4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devhelp-devel-0.9.2-2.4.4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devhelp-devel-0.9.2-2.4.4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devhelp-devel-0.9.2-2.4.4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'devhelp / devhelp-devel');
}
