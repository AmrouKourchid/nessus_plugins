#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:060. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17176);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2005-0094",
    "CVE-2005-0095",
    "CVE-2005-0096",
    "CVE-2005-0097",
    "CVE-2005-0173",
    "CVE-2005-0174",
    "CVE-2005-0175",
    "CVE-2005-0211",
    "CVE-2005-0241"
  );
  script_xref(name:"RHSA", value:"2005:060");

  script_name(english:"RHEL 4 : squid (RHSA-2005:060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for squid.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2005:060 advisory.

    Squid is a full-featured Web proxy cache.

    A buffer overflow flaw was found in the Gopher relay parser. This bug
    could allow a remote Gopher server to crash the Squid proxy that reads data
    from it. Although Gopher servers are now quite rare, a malicious webpage
    (for example) could redirect or contain a frame pointing to an attacker's
    malicious gopher server. The Common Vulnerabilities and Exposures project
    (cve.mitre.org) has assigned the name CAN-2005-0094 to this issue.

    An integer overflow flaw was found in the WCCP message parser. It is
    possible to crash the Squid server if an attacker is able to send a
    malformed WCCP message with a spoofed source address matching Squid's
    home router. The Common Vulnerabilities and Exposures project
    (cve.mitre.org) has assigned the name CAN-2005-0095 to this issue.

    A memory leak was found in the NTLM fakeauth_auth helper. It is possible
    that an attacker could place the Squid server under high load, causing the
    NTML fakeauth_auth helper to consume a large amount of memory, resulting in
    a denial of service. The Common Vulnerabilities and Exposures project
    (cve.mitre.org) has assigned the name CAN-2005-0096 to this issue.

    A NULL pointer de-reference bug was found in the NTLM fakeauth_auth helper.
    It is possible for an attacker to send a malformed NTLM type 3 message,
    causing the Squid server to crash. The Common Vulnerabilities and
    Exposures project (cve.mitre.org) has assigned the name CAN-2005-0097 to
    this issue.

    A username validation bug was found in squid_ldap_auth. It is possible for
    a username to be padded with spaces, which could allow a user to bypass
    explicit access control rules or confuse accounting. The Common
    Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
    CAN-2005-0173 to this issue.

    The way Squid handles HTTP responses was found to need strengthening. It is
    possible that a malicious Web server could send a series of HTTP responses
    in such a way that the Squid cache could be poisoned, presenting users with
    incorrect webpages. The Common Vulnerabilities and Exposures project
    (cve.mitre.org) has assigned the names CAN-2005-0174 and CAN-2005-0175 to
    these issues.

    A bug was found in the way Squid handled oversized HTTP response headers.
    It is possible that a malicious Web server could send a specially crafted
    HTTP header which could cause the Squid cache to be poisoned, presenting
    users with incorrect webpages. The Common Vulnerabilities and Exposures
    project (cve.mitre.org) has assigned the name CAN-2005-0241 to this issue.

    A buffer overflow bug was found in the WCCP message parser. It is possible
    that an attacker could send a malformed WCCP message which could crash the
    Squid server or execute arbitrary code. The Common Vulnerabilities and
    Exposures project (cve.mitre.org) has assigned the name CAN-2005-0211
    to this issue.

    Users of Squid should upgrade to this updated package, which contains
    backported patches, and is not vulnerable to these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_060.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8344b53b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=145545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=146161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=146779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=146785");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2005_1.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2005_2.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2005_3.txt");
  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-ldap_spaces
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96864d1c");
  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-fakeauth_auth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af6b5d37");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:060");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL squid package based on the guidance in RHSA-2005:060.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0211");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2005-0097");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
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
      {'reference':'squid-2.5.STABLE6-3.4E.3', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'squid-2.5.STABLE6-3.4E.3', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'squid-2.5.STABLE6-3.4E.3', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'squid-2.5.STABLE6-3.4E.3', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'squid-2.5.STABLE6-3.4E.3', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid');
}
