#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:1335. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216436);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2024-1135",
    "CVE-2024-4340",
    "CVE-2024-7246",
    "CVE-2024-26130",
    "CVE-2024-27306",
    "CVE-2024-30251",
    "CVE-2024-34064",
    "CVE-2024-35195",
    "CVE-2024-39614",
    "CVE-2024-41989",
    "CVE-2024-41990",
    "CVE-2024-41991",
    "CVE-2024-42005"
  );
  script_xref(name:"RHSA", value:"2025:1335");

  script_name(english:"RHEL 8 : RHUI 4.11 (RHSA-2025:1335)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:1335 advisory.

    Red Hat Update Infrastructure (RHUI) provides a highly scalable and redundant framework for managing
    repositories and content. It also allows cloud providers to deliver content and updates to Red Hat
    Enterprise Linux (RHEL) instances.

    Security Fixes:
    * Cryptography: NULL pointer dereference with pkcs12.serialize_key_and_certificates when called with a
    non-matching certificate and private key and an hmac_hash override (CVE-2024-26130)

    * Gunicorn: HTTP Request Smuggling due to improper validation of Transfer-Encoding headers (CVE-2024-1135)

    * Aiohttp: aiohttp: XSS on index pages for static file handling (CVE-2024-27306)

    * Aiohttp: aiohttp: DoS when trying to parse malformed POST requests (CVE-2024-30251)

    * Sqlparse: sqlparse: parsing heavily nested list leads to denial of service (CVE-2024-4340)

    * Jinja2: jinja2: accepts keys containing non-attribute characters (CVE-2024-34064)

    * Django: Potential denial-of-service in django.utils.translation.get_supported_language_variant()
    (CVE-2024-39614)

    * Django: Memory exhaustion in django.utils.numberformat.floatformat() (CVE-2024-41989)

    * Django: Potential SQL injection in QuerySet.values() and values_list() (CVE-2024-42005)

    * Django: Potential denial-of-service vulnerability in django.utils.html.urlize() (CVE-2024-41990)

    * Django: Potential denial-of-service vulnerability in django.utils.html.urlize() and AdminURLFieldWidget
    (CVE-2024-41991)

    * Grpcio: client communicating with a HTTP/2 proxy can poison the HPACK table between the proxy and the
    backend (CVE-2024-7246)

    * Requests: subsequent requests to the same host ignore cert verification (CVE-2024-35195)

    For detailed information on other changes in this release, see the Red Hat Update Infrastructure Release
    Notes linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://docs.redhat.com/en/documentation/red_hat_update_infrastructure/4/html/release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f823164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302436");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-429");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-577");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-617");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_1335.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26d5d491");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:1335");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:N/R:U/V:D/RE:M/U:Amber");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42005");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-1135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 80, 89, 130, 400, 440, 444, 476, 670, 674, 835, 1287);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-sqlparse");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/x86_64/rhui/4/debug',
      'content/dist/layered/rhel8/x86_64/rhui/4/os',
      'content/dist/layered/rhel8/x86_64/rhui/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3.11-aiohttp-3.9.4-1.el8ui', 'cpu':'x86_64', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-27306', 'CVE-2024-30251']},
      {'reference':'python3.11-cryptography-42.0.8-1.el8ui', 'cpu':'x86_64', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-26130']},
      {'reference':'python3.11-django-4.2.15-1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-39614', 'CVE-2024-41989', 'CVE-2024-41990', 'CVE-2024-41991', 'CVE-2024-42005']},
      {'reference':'python3.11-grpcio-1.65.4-1.el8ui', 'cpu':'x86_64', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-7246']},
      {'reference':'python3.11-gunicorn-22.0.0-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-1135']},
      {'reference':'python3.11-jinja2-3.1.4-1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-34064']},
      {'reference':'python3.11-requests-2.32.3-2.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-sqlparse-0.5.0-1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-4340']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3.11-aiohttp / python3.11-cryptography / python3.11-django / etc');
}
