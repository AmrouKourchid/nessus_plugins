#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1878. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-36053",
    "CVE-2023-37276",
    "CVE-2023-41164",
    "CVE-2023-43665",
    "CVE-2023-47627",
    "CVE-2023-49081",
    "CVE-2023-49082",
    "CVE-2023-49083",
    "CVE-2024-22195",
    "CVE-2024-23334",
    "CVE-2024-23342",
    "CVE-2024-23829",
    "CVE-2024-24680",
    "CVE-2024-27351"
  );
  script_xref(name:"RHSA", value:"2024:1878");

  script_name(english:"RHEL 8 : RHUI 4.8 Release - Security Updates, Bug Fixes, and Enhancements (Moderate) (RHSA-2024:1878)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:1878 advisory.

    Red Hat Update Infrastructure (RHUI) offers a highly scalable, highly redundant
    framework that enables you to manage repositories and content. It also enables
    cloud providers to deliver content and updates to Red Hat Enterprise Linux
    (RHEL) instances.

    Security Fix(es):

    * python-django: Potential regular expression denial of service vulnerability in
    EmailValidator/URLValidator (CVE-2023-36053)

    * python-aiohttp: HTTP request smuggling via llhttp HTTP request parser (CVE-2023-37276)

    * python-django: Potential denial of service vulnerability in ``django.utils.encoding.uri_to_iri()``
    (CVE-2023-41164)

    * python-django: Denial-of-service possibility in django.utils.text.Truncator (CVE-2023-43665)

    * python-aiohttp: numerous issues in HTTP parser with header parsing (CVE-2023-47627)

    * aiohttp: HTTP request modification (CVE-2023-49081)

    * python-cryptography: NULL-dereference when loading PKCS7 certificates (CVE-2023-49083)

    * jinja2: HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195)

    * aiohttp: follow_symlinks directory traversal vulnerability (CVE-2024-23334)

    * python-ecdsa: vulnerable to the Minerva attack (CVE-2024-23342)

    * python-aiohttp: http request smuggling (CVE-2024-23829)

    * Django: denial-of-service in ``intcomma`` template filter (CVE-2024-24680)

    * python-django: Potential regular expression denial-of-service in django.utils.text.Truncator.words()
    (CVE-2024-27351)

    * aiohttp: CRLF injection if user controls the HTTP method using aiohttp client (CVE-2023-49082)

    This RHUI update fixes the following bugs:

    * The rhui-installer failed on RHEL 8.10 Beta due to the use of distutils. This has been addressed by
    updating to a newer version of ansible-collection-community-crypto which does not use the distutils.

    This RHUI update introduces the following enhancements:

    * A native Ansible module is now used to update the packages on the RHUA server when the RHUI installer is
    run for the first time or rerun at any time. This update can be prevented by using the --ignore-newer-
    rhel-packages flag on the rhui-installer command line.

    * PulpCore has been updated to version 3.39.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1878.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2174df9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266045");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-434");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-514");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1878");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23334");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-49083");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 79, 93, 385, 400, 444, 476, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jinja2");
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
      {'reference':'python3.11-aiohttp-3.9.2-1.el8ui', 'cpu':'x86_64', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-47627', 'CVE-2023-49081', 'CVE-2023-49082', 'CVE-2024-23334', 'CVE-2024-23829']},
      {'reference':'python3.11-cryptography-41.0.6-1.el8ui', 'cpu':'x86_64', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-49083']},
      {'reference':'python3.11-django-4.2.11-1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-36053', 'CVE-2023-41164', 'CVE-2023-43665', 'CVE-2024-24680', 'CVE-2024-27351']},
      {'reference':'python3.11-ecdsa-0.18.0-4.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-23342']},
      {'reference':'python3.11-jinja2-3.1.3-1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-22195']}
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
