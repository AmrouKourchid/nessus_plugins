#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4285. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170302);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-16935",
    "CVE-2019-18348",
    "CVE-2019-20907",
    "CVE-2019-20916",
    "CVE-2020-8492",
    "CVE-2020-14422",
    "CVE-2020-26116"
  );
  script_xref(name:"RHSA", value:"2020:4285");

  script_name(english:"RHEL 6 / 7 : rh-python36 (RHSA-2020:4285)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4285 advisory.

    Python is an interpreted, interactive, object-oriented programming language, which includes modules,
    classes, exceptions, very high level dynamic data types and dynamic typing. Python supports interfaces to
    many system calls and libraries, as well as to various windowing systems.

    The following packages have been upgraded to a later upstream version: rh-python36-python (3.6.12).
    (BZ#1873080)

    Security Fix(es):

    * python: XSS vulnerability in the documentation XML-RPC server in server_title field (CVE-2019-16935)

    * python: CRLF injection via the host part of the url passed to urlopen() (CVE-2019-18348)

    * python: infinite loop in the tarfile module via crafted TAR archive (CVE-2019-20907)

    * python-pip: directory traversal in _download_http_url() function in src/pip/_internal/download.py
    (CVE-2019-20916)

    * python: wrong backtracking in urllib.request.AbstractBasicAuthHandler allows for a ReDoS (CVE-2020-8492)

    * python: DoS via inefficiency in IPv{4,6}Interface classes (CVE-2020-14422)

    * python: CRLF injection via HTTP request method in httplib/http.client (CVE-2020-26116)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * rh-python36-python-pip: Contains multiple bundled libraries, and has no bundled() provides (BZ#1774951)

    * Allow rh-python36-python-pip to use system CA certificate Trust (BZ#1826520)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_4285.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9627a2b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1727276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1763229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1809065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1826520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1854926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1868135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1883014");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26116");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-20916");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 113, 400, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-python36-python-virtualenv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-python36-python-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-debug-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-devel-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-libs-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-pip-9.0.1-5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-test-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-tkinter-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-tools-3.6.12-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-virtualenv-15.1.0-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-python36-python-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-debug-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-devel-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-libs-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-pip-9.0.1-5.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-test-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-tkinter-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-tools-3.6.12-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-python36-python-virtualenv-15.1.0-3.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-python36-python / rh-python36-python-debug / etc');
}
