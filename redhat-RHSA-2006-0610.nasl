#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0610. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22121);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2006-2776",
    "CVE-2006-2778",
    "CVE-2006-2779",
    "CVE-2006-2780",
    "CVE-2006-2782",
    "CVE-2006-2783",
    "CVE-2006-2784",
    "CVE-2006-2785",
    "CVE-2006-2786",
    "CVE-2006-2787",
    "CVE-2006-2788",
    "CVE-2006-3113",
    "CVE-2006-3677",
    "CVE-2006-3801",
    "CVE-2006-3802",
    "CVE-2006-3803",
    "CVE-2006-3805",
    "CVE-2006-3806",
    "CVE-2006-3807",
    "CVE-2006-3808",
    "CVE-2006-3809",
    "CVE-2006-3810",
    "CVE-2006-3811",
    "CVE-2006-3812"
  );
  script_xref(name:"RHSA", value:"2006:0610");

  script_name(english:"RHEL 4 : firefox (RHSA-2006:0610)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for firefox.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2006:0610 advisory.

    Mozilla Firefox is an open source Web browser.

    The Mozilla Foundation has discontinued support for the Mozilla Firefox
    1.0 branch. This update deprecates the Mozilla Firefox 1.0 branch in
    Red Hat Enterprise Linux 4 in favor of the supported Mozilla Firefox
    1.5 branch.

    This update also resolves a number of outstanding Firefox security issues:

    Several flaws were found in the way Firefox processed certain javascript
    actions. A malicious web page could execute arbitrary javascript
    instructions with the permissions of chrome, allowing the page to steal
    sensitive information or install browser malware. (CVE-2006-2776,
    CVE-2006-2784, CVE-2006-2785, CVE-2006-2787, CVE-2006-3807, CVE-2006-3809,
    CVE-2006-3812)

    Several denial of service flaws were found in the way Firefox processed
    certain web content. A malicious web page could crash the browser or
    possibly execute arbitrary code as the user running Firefox.
    (CVE-2006-2779, CVE-2006-2780, CVE-2006-3801, CVE-2006-3677, CVE-2006-3113,
    CVE-2006-3803, CVE-2006-3805, CVE-2006-3806, CVE-2006-3811)

    A cross-site scripting flaw was found in the way Firefox processed
    Unicode Byte-Order-Mark (BOM) markers in UTF-8 web pages. A malicious web
    page could execute a script within the browser that a web input sanitizer
    could miss due to a malformed script tag. (CVE-2006-2783)

    Several flaws were found in the way Firefox processed certain javascript
    actions. A malicious web page could conduct a cross-site scripting attack
    or steal sensitive information (such as cookies owned by other domains).
    (CVE-2006-3802, CVE-2006-3810)

    A form file upload flaw was found in the way Firefox handled javascript
    input object mutation. A malicious web page could upload an arbitrary local
    file at form submission time without user interaction. (CVE-2006-2782)

    A denial of service flaw was found in the way Firefox called the
    crypto.signText() javascript function. A malicious web page could crash the
    browser if the victim had a client certificate loaded. (CVE-2006-2778)

    Two HTTP response smuggling flaws were found in the way Firefox processed
    certain invalid HTTP response headers. A malicious web site could return
    specially crafted HTTP response headers which may bypass HTTP proxy
    restrictions. (CVE-2006-2786)

    A flaw was found in the way Firefox processed Proxy AutoConfig scripts. A
    malicious Proxy AutoConfig server could execute arbitrary javascript
    instructions with the permissions of chrome, allowing the page to steal
    sensitive information or install browser malware. (CVE-2006-3808)

    A double free flaw was found in the way the nsIX509::getRawDER method was
    called. If a victim visited a carefully crafted web page, it was possible
    to execute arbitrary code as the user running Firefox. (CVE-2006-2788)

    Users of Firefox are advised to upgrade to this update, which contains
    Firefox version 1.5.0.5 that corrects these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2006/rhsa-2006_0610.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?437b5b7a");
  script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=193895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=196973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=200168");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2006:0610");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL firefox package based on the guidance in RHSA-2006:0610.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-2787");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2006-3810");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2006-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'firefox-1.5.0.5-0.el4.1', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'firefox-1.5.0.5-0.el4.1', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'firefox-1.5.0.5-0.el4.1', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'firefox-1.5.0.5-0.el4.1', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'firefox-1.5.0.5-0.el4.1', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
