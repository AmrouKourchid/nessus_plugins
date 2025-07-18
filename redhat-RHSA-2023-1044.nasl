#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1044. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172042);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2019-11358",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2021-35065",
    "CVE-2021-44906",
    "CVE-2022-1274",
    "CVE-2022-1438",
    "CVE-2022-1471",
    "CVE-2022-2764",
    "CVE-2022-3916",
    "CVE-2022-4137",
    "CVE-2022-24785",
    "CVE-2022-25857",
    "CVE-2022-31129",
    "CVE-2022-37603",
    "CVE-2022-38749",
    "CVE-2022-38750",
    "CVE-2022-38751",
    "CVE-2022-40149",
    "CVE-2022-40150",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-45047",
    "CVE-2022-45693",
    "CVE-2022-46175",
    "CVE-2022-46363",
    "CVE-2022-46364",
    "CVE-2023-0091",
    "CVE-2023-0264"
  );
  script_xref(name:"RHSA", value:"2023:1044");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"RHEL 8 : Red Hat Single Sign-On 7.6.2 security update on RHEL 8 (Important) (RHSA-2023:1044)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Single Sign-On 7.6.2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:1044 advisory.

    Red Hat Single Sign-On 7.6 is a standalone server, based on the Keycloak project, that provides
    authentication and standards-based single sign-on capabilities for web and mobile applications.

    This release of Red Hat Single Sign-On 7.6.2 on RHEL 8 serves as a replacement for Red Hat Single Sign-On
    7.6.1, and includes bug fixes and enhancements, which are documented in the Release Notes document linked
    to in the References.

    Security Fix(es):
    * keycloak: XSS on impersonation under specific circumstances (CVE-2022-1438)
    * Moment.js: Path traversal in moment.locale (CVE-2022-24785)
    * keycloak: missing email notification template allowlist (CVE-2022-1274)
    * keycloak: minimist: prototype pollution (CVE-2021-44906)
    * moment: inefficient parsing algorithm resulting in DoS (CVE-2022-31129)
    * undertow: DoS can be achieved as Undertow server waits for the LAST_CHUNK forever for EJB invocations
    (CVE-2022-2764)
    * snakeyaml: Denial of Service due to missing nested depth limitation for collections (CVE-2022-25857)
    * loader-utils: loader-utils:Regular expression denial of service (CVE-2022-37603)
    * keycloak: Session takeover with OIDC offline refreshtokens (CVE-2022-3916)
    * keycloak: path traversal via double URL encoding (CVE-2022-3782)
    * snakeyaml: Uncaught exception in org.yaml.snakeyaml.composer.Composer.composeSequenceNode
    (CVE-2022-38749)
    * snakeyaml: Uncaught exception in java.base/java.util.regex.Pattern$Ques.match (CVE-2022-38751)
    * snakeyaml: Uncaught exception in org.yaml.snakeyaml.constructor.BaseConstructor.constructObject
    (CVE-2022-38750)
    * keycloak: Client Registration endpoint does not check token revocation (CVE-2023-0091)
    * keycloak: glob-parent: Regular Expression Denial of Service (CVE-2021-35065)
    * json5: Prototype Pollution in JSON5 via Parse Method (CVE-2022-46175)
    * keycloak: keycloak: user impersonation via stolen uuid code (CVE-2023-0264)
    * snakeyaml: Constructor Deserialization Remote Code Execution (CVE-2022-1471)
    * CXF: Apache CXF: SSRF Vulnerability (CVE-2022-46364)
    * rcue-bootstrap: bootstrap: Cross-site Scripting (XSS) in the data-container property of tooltip
    (CVE-2018-14042)
    * jettison: If the value in map is the map's self, the new new JSONObject(map) cause StackOverflowError
    which may lead to dos (CVE-2022-45693)
    * sshd-common: mina-sshd: Java unsafe deserialization vulnerability (CVE-2022-45047)
    * jettison: memory exhaustion via user-supplied XML or JSON data (CVE-2022-40150)
    * jettison: parser crash by stackoverflow (CVE-2022-40149)
    * jackson-databind: use of deeply nested arrays (CVE-2022-42004)
    * jackson-databind: deep wrapper array nesting wrt UNWRAP_SINGLE_VALUE_ARRAYS (CVE-2022-42003)
    * jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)
    * jquery: Passing HTML containing <option> elements to manipulation methods could result in untrusted code
    execution (CVE-2020-11023)
    * bootstrap: Cross-site Scripting (XSS) in the collapse data-parent attribute (CVE-2018-14040)
    * jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution,
    or property injection (CVE-2019-11358)
    * CXF: Apache CXF: directory listing / code exfiltration (CVE-2022-46363)
    * keycloak: reflected XSS attack (CVE-2022-4137)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_1044.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba5cbcc9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1601614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1601617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1701972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2066009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2072009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2073157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2105075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2117506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2126789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2129706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2129707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2129709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2138971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2140597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2141404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2145194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2148496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2150009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2158585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2160585");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Single Sign-On 7.6.2 package based on the guidance in RHSA-2023:1044.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 79, 80, 81, 185, 303, 384, 400, 502, 787, 918, 1321);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rh-sso/7.6/debug',
      'content/dist/layered/rhel8/x86_64/rh-sso/7.6/os',
      'content/dist/layered/rhel8/x86_64/rh-sso/7.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-sso7-keycloak-18.0.6-1.redhat_00001.1.el8sso', 'release':'8', 'el_string':'el8sso', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'},
      {'reference':'rh-sso7-keycloak-server-18.0.6-1.redhat_00001.1.el8sso', 'release':'8', 'el_string':'el8sso', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-sso7-keycloak / rh-sso7-keycloak-server');
}
