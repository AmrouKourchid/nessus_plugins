#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0094. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44430);
  script_version("1.42");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/21");

  script_cve_id(
    "CVE-2009-4242",
    "CVE-2009-4245",
    "CVE-2009-4247",
    "CVE-2009-4248",
    "CVE-2009-4257",
    "CVE-2010-0416",
    "CVE-2010-0417",
    "CVE-2010-4376"
  );
  script_bugtraq_id(37880);
  script_xref(name:"RHSA", value:"2010:0094");

  script_name(english:"RHEL 4 : HelixPlayer (RHSA-2010:0094)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for HelixPlayer.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2010:0094 advisory.

  - HelixPlayer / RealPlayer: GIF file heap overflow (CVE-2009-4242)

  - HelixPlayer / RealPlayer: compressed GIF heap overflow (CVE-2009-4245)

  - HelixPlayer / RealPlayer: RTSP client ASM RuleBook stack buffer overflow (CVE-2009-4247)

  - HelixPlayer / RealPlayer: RTSP SET_PARAMETER buffer overflow (CVE-2009-4248)

  - HelixPlayer / RealPlayer: SMIL getAtom heap buffer overflow (CVE-2009-4257)

  - HelixPlayer / RealPlayer: URL unescape buffer overflow (CVE-2010-0416)

  - HelixPlayer / RealPlayer: rule book handling heap corruption (CVE-2010-0417)

  - HelixPlayer multiple flaws (CVE-2010-2997, CVE-2010-4375, CVE-2010-4378, CVE-2010-4379, CVE-2010-4382,
    CVE-2010-4383, CVE-2010-4385, CVE-2010-4386, CVE-2010-4392, CVE-2010-4376) (CVE-2010-4376)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0094.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a59bcd12");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0094");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=561860");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL HelixPlayer package based on the guidance in RHSA-2010:0094.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4376");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-4242");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(121, 122);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'HelixPlayer-1.0.6-1.el4_8.1', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'HelixPlayer-1.0.6-1.el4_8.1', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'HelixPlayer');
}
