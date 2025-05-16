#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1434. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56740);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2011-2094",
    "CVE-2011-2095",
    "CVE-2011-2096",
    "CVE-2011-2097",
    "CVE-2011-2098",
    "CVE-2011-2099",
    "CVE-2011-2101",
    "CVE-2011-2104",
    "CVE-2011-2105",
    "CVE-2011-2107",
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2424",
    "CVE-2011-2425",
    "CVE-2011-2426",
    "CVE-2011-2427",
    "CVE-2011-2428",
    "CVE-2011-2429",
    "CVE-2011-2430",
    "CVE-2011-2431",
    "CVE-2011-2432",
    "CVE-2011-2433",
    "CVE-2011-2434",
    "CVE-2011-2435",
    "CVE-2011-2436",
    "CVE-2011-2437",
    "CVE-2011-2438",
    "CVE-2011-2439",
    "CVE-2011-2440",
    "CVE-2011-2442",
    "CVE-2011-2444",
    "CVE-2011-4374"
  );
  script_bugtraq_id(
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49186,
    49572,
    49575,
    49576,
    49577,
    49578,
    49579,
    49580,
    49582,
    49583,
    49584,
    49585,
    49710,
    49714,
    49715,
    49716,
    49717,
    49718
  );
  script_xref(name:"RHSA", value:"2011:1434");

  script_name(english:"RHEL 6 : acroread (RHSA-2011:1434)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for acroread.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:1434 advisory.

    Adobe Reader allows users to view and print documents in Portable Document
    Format (PDF).

    This update fixes multiple security flaws in Adobe Reader. These flaws are
    detailed on the Adobe security page APSB11-24, listed in the References
    section. A specially-crafted PDF file could cause Adobe Reader to crash or,
    potentially, execute arbitrary code as the user running Adobe Reader when
    opened. (CVE-2011-2431, CVE-2011-2432, CVE-2011-2433, CVE-2011-2434,
    CVE-2011-2435, CVE-2011-2436, CVE-2011-2437, CVE-2011-2438, CVE-2011-2439,
    CVE-2011-2440, CVE-2011-2442)

    This update also fixes multiple security flaws in Adobe Flash Player
    embedded in Adobe Reader. These flaws are detailed on the Adobe security
    pages APSB11-21 and APSB11-26, listed in the References section.

    A PDF file with an embedded, specially-crafted SWF file could cause Adobe
    Reader to crash or, potentially, execute arbitrary code as the user running
    Adobe Reader when opened. (CVE-2011-2130, CVE-2011-2134, CVE-2011-2135,
    CVE-2011-2136, CVE-2011-2137, CVE-2011-2138, CVE-2011-2139, CVE-2011-2140,
    CVE-2011-2414, CVE-2011-2415, CVE-2011-2416, CVE-2011-2417, CVE-2011-2424,
    CVE-2011-2425, CVE-2011-2426, CVE-2011-2427, CVE-2011-2428, CVE-2011-2430)

    A flaw in Adobe Flash Player could allow an attacker to conduct cross-site
    scripting (XSS) attacks if a victim were tricked into visiting a
    specially-crafted web page. (CVE-2011-2444)

    This update also fixes an information disclosure flaw in Adobe Flash
    Player. (CVE-2011-2429)

    All Adobe Reader users should install these updated packages. They contain
    Adobe Reader version 9.4.6, which is not vulnerable to these issues. All
    running instances of Adobe Reader must be restarted for the update to take
    effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-26.html");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_1434.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18e4b66f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=729497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=740201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=740204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=740388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=749381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1434");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL acroread package based on the guidance in RHSA-2011:1434.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2425");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-2444");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/client/6/6Client/i386/supplementary/debug',
      'content/dist/rhel/client/6/6Client/i386/supplementary/os',
      'content/dist/rhel/client/6/6Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/os',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/supplementary/debug',
      'content/dist/rhel/server/6/6Server/i386/supplementary/os',
      'content/dist/rhel/server/6/6Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/os',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'acroread-9.4.6-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'acroread-plugin-9.4.6-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'acroread / acroread-plugin');
}
