#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4003. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194327);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-28327",
    "CVE-2022-41715",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24539",
    "CVE-2023-29400"
  );
  script_xref(name:"RHSA", value:"2023:4003");

  script_name(english:"RHEL 8 / 9 : Red Hat Service Interconnect 1.4 Release (RHSA-2023:4003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Service Interconnect 1.4 Release.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:4003 advisory.

    As a Kubernetes user, I cannot connect easily connect services from one cluster with services on another
    cluster. Red Hat Application Interconnect enables me to create a service network and it allows
    geographically distributed services to connect as if they were all running in the same site.

    Security Fix(es):

    * golang: archive/tar: unbounded memory consumption when reading headers (CVE-2022-2879)

    * golang: net/http/httputil: ReverseProxy should not forward unparseable query parameters (CVE-2022-2880)

    * golang: crypto/elliptic: panic caused by oversized scalar (CVE-2022-28327)

    * golang: regexp/syntax: limit memory used by parsing regexps (CVE-2022-41715)

    * net/http, golang.org/x/net/http2: avoid quadratic complexity in HPACK decoding (CVE-2022-41723)

    * golang: crypto/tls: large handshake records may cause panics (CVE-2022-41724)

    * golang: net/http, mime/multipart: denial of service from excessive resource consumption (CVE-2022-41725)

    * golang: net/http, net/textproto: denial of service from excessive memory allocation (CVE-2023-24534)

    * golang: net/http, net/textproto, mime/multipart: denial of service from excessive resource consumption
    (CVE-2023-24536)

    * golang: go/parser: Infinite loop in parsing (CVE-2023-24537)

    * golang: html/template: backticks not treated as string delimiters (CVE-2023-24538)

    * golang: html/template: improper sanitization of CSS values (CVE-2023-24539)

    * golang: html/template: improper handling of empty HTML attributes (CVE-2023-29400)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_4003.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c56b3e9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_service_interconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbe0b66e");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2077689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2132867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2132868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2132872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196029");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4003");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Service Interconnect 1.4 Release package based on the guidance in RHSA-2023:4003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28327");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-24538");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 176, 190, 400, 444, 770, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skupper-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skupper-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skupper-router-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skupper-router-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skupper-router-tools");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rhsi/1/debug',
      'content/dist/layered/rhel8/x86_64/rhsi/1/os',
      'content/dist/layered/rhel8/x86_64/rhsi/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'skupper-cli-1.4.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2879', 'CVE-2022-2880', 'CVE-2022-28327', 'CVE-2022-41715', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537', 'CVE-2023-24538', 'CVE-2023-24539', 'CVE-2023-29400']},
      {'reference':'skupper-router-2.4.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-common-2.4.1-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-docs-2.4.1-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-tools-2.4.1-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/rhsi/1/debug',
      'content/dist/layered/rhel9/x86_64/rhsi/1/os',
      'content/dist/layered/rhel9/x86_64/rhsi/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'skupper-cli-1.4.1-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2879', 'CVE-2022-2880', 'CVE-2022-28327', 'CVE-2022-41715', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537', 'CVE-2023-24538', 'CVE-2023-24539', 'CVE-2023-29400']},
      {'reference':'skupper-router-2.4.1-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-common-2.4.1-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-docs-2.4.1-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']},
      {'reference':'skupper-router-tools-2.4.1-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-41715']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'skupper-cli / skupper-router / skupper-router-common / etc');
}
