#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2905. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103957);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2014-9970",
    "CVE-2017-12158",
    "CVE-2017-12159",
    "CVE-2017-12160",
    "CVE-2017-12197"
  );
  script_xref(name:"RHSA", value:"2017:2905");

  script_name(english:"RHEL 7 : rh-sso7-keycloak (RHSA-2017:2905)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rh-sso7-keycloak.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2905 advisory.

    Red Hat Single Sign-On is a standalone server, based on the Keycloak project, that provides authentication
    and standards-based single sign-on capabilities for web and mobile applications.

    This release of Red Hat Single Sign-On 7.1.3 serves as a replacement for Red Hat Single Sign-On 7.1.2, and
    includes several bug fixes and enhancements. For further information, refer to the Release Notes linked to
    in the References section.

    Security Fix(es):

    * It was found that keycloak would accept a HOST header URL in the admin console and use it to determine
    web resource locations. An attacker could use this flaw against an authenticated user to attain reflected
    XSS via a malicious server. (CVE-2017-12158)

    * It was found that the cookie used for CSRF prevention in Keycloak was not unique to each session. An
    attacker could use this flaw to gain access to an authenticated user session, leading to possible
    information disclosure or further attacks. (CVE-2017-12159)

    * It was found that libpam4j did not properly validate user accounts when authenticating. A user with a
    valid password for a disabled account would be able to bypass security restrictions and possibly access
    sensitive information. (CVE-2017-12197)

    * It was found that Keycloak oauth would permit an authenticated resource to obtain an access/refresh
    token pair from the authentication server, permitting indefinite usage in the case of permission
    revocation. An attacker on an already compromised resource could use this flaw to grant himself continued
    permissions and possibly conduct further attacks. (CVE-2017-12160)

    Red Hat would like to thank Mykhailo Stadnyk (Playtech) for reporting CVE-2017-12158; Prapti Mittal for
    reporting CVE-2017-12159; and Bart Toersche (Simacan) for reporting CVE-2017-12160. The CVE-2017-12197
    issue was discovered by Christian Heimes (Red Hat).

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_2905.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03ef35a9");
  # https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.1/html/release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0187894");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2905");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1484111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1484154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1489161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1503103");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHSSO-1122");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rh-sso7-keycloak package based on the guidance in RHSA-2017:2905.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12160");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-12159");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(285, 385, 444, 613, 863);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-sso7-keycloak-2.5.14-1.Final_redhat_1.1.jbcs.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'},
      {'reference':'rh-sso7-keycloak-server-2.5.14-1.Final_redhat_1.1.jbcs.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-sso7-keycloak / rh-sso7-keycloak-server');
}
