##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4442. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142429);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-5018",
    "CVE-2019-16168",
    "CVE-2019-20218",
    "CVE-2020-6405",
    "CVE-2020-9327",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632"
  );
  script_bugtraq_id(108294);
  script_xref(name:"RHSA", value:"2020:4442");
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"RHEL 8 : sqlite (RHSA-2020:4442)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for sqlite.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4442 advisory.

    SQLite is a C library that implements an SQL database engine. A large subset of SQL92 is supported. A
    complete database is stored in a single disk file. The API is designed for convenience and ease of use.
    Applications that link against SQLite can enjoy the power and flexibility of an SQL database without the
    administrative hassles of supporting a separate database server.

    Security Fix(es):

    * sqlite: Use-after-free in window function leading to remote code execution (CVE-2019-5018)

    * sqlite: Division by zero in whereLoopAddBtreeIndex in sqlite3.c (CVE-2019-16168)

    * sqlite: selectExpander in select.c proceeds with WITH stack unwinding even after a parsing error
    (CVE-2019-20218)

    * sqlite: Out-of-bounds read in SELECT with ON/USING clause (CVE-2020-6405)

    * sqlite: NULL pointer dereference and segmentation fault because of generated column optimizations
    (CVE-2020-9327)

    * sqlite: Use-after-free in fts3EvalNextRow in ext/fts3/fts3.c (CVE-2020-13630)

    * sqlite: Virtual table can be renamed into the name of one of its shadow tables (CVE-2020-13631)

    * sqlite: NULL pointer dereference in ext/fts3/fts3_snippet.c via a crafted matchinfo() query
    (CVE-2020-13632)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.3 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_4442.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bcb6f95");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.3_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7e37d18");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1768986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1791313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1801181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1809315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1841562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1841568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1841574");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL sqlite package based on the guidance in RHSA-2020:4442.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5018");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 125, 369, 391, 416, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sqlite-libs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel8/8.10/aarch64/appstream/debug',
      'content/dist/rhel8/8.10/aarch64/appstream/os',
      'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/aarch64/baseos/debug',
      'content/dist/rhel8/8.10/aarch64/baseos/os',
      'content/dist/rhel8/8.10/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/appstream/debug',
      'content/dist/rhel8/8.10/ppc64le/appstream/os',
      'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/baseos/debug',
      'content/dist/rhel8/8.10/ppc64le/baseos/os',
      'content/dist/rhel8/8.10/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/appstream/debug',
      'content/dist/rhel8/8.10/s390x/appstream/os',
      'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/baseos/debug',
      'content/dist/rhel8/8.10/s390x/baseos/os',
      'content/dist/rhel8/8.10/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/appstream/debug',
      'content/dist/rhel8/8.10/x86_64/appstream/os',
      'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/baseos/debug',
      'content/dist/rhel8/8.10/x86_64/baseos/os',
      'content/dist/rhel8/8.10/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/appstream/debug',
      'content/dist/rhel8/8.6/aarch64/appstream/os',
      'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/baseos/debug',
      'content/dist/rhel8/8.6/aarch64/baseos/os',
      'content/dist/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/appstream/debug',
      'content/dist/rhel8/8.6/ppc64le/appstream/os',
      'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/baseos/debug',
      'content/dist/rhel8/8.6/ppc64le/baseos/os',
      'content/dist/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/appstream/debug',
      'content/dist/rhel8/8.6/s390x/appstream/os',
      'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/baseos/debug',
      'content/dist/rhel8/8.6/s390x/baseos/os',
      'content/dist/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/appstream/debug',
      'content/dist/rhel8/8.6/x86_64/appstream/os',
      'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/baseos/debug',
      'content/dist/rhel8/8.6/x86_64/baseos/os',
      'content/dist/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/appstream/debug',
      'content/dist/rhel8/8.8/aarch64/appstream/os',
      'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/baseos/debug',
      'content/dist/rhel8/8.8/aarch64/baseos/os',
      'content/dist/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/appstream/debug',
      'content/dist/rhel8/8.8/ppc64le/appstream/os',
      'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/baseos/debug',
      'content/dist/rhel8/8.8/ppc64le/baseos/os',
      'content/dist/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/appstream/debug',
      'content/dist/rhel8/8.8/s390x/appstream/os',
      'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/baseos/debug',
      'content/dist/rhel8/8.8/s390x/baseos/os',
      'content/dist/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/appstream/debug',
      'content/dist/rhel8/8.8/x86_64/appstream/os',
      'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/baseos/debug',
      'content/dist/rhel8/8.8/x86_64/baseos/os',
      'content/dist/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/appstream/debug',
      'content/dist/rhel8/8.9/aarch64/appstream/os',
      'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/baseos/debug',
      'content/dist/rhel8/8.9/aarch64/baseos/os',
      'content/dist/rhel8/8.9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/appstream/debug',
      'content/dist/rhel8/8.9/ppc64le/appstream/os',
      'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/baseos/debug',
      'content/dist/rhel8/8.9/ppc64le/baseos/os',
      'content/dist/rhel8/8.9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/appstream/debug',
      'content/dist/rhel8/8.9/s390x/appstream/os',
      'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/baseos/debug',
      'content/dist/rhel8/8.9/s390x/baseos/os',
      'content/dist/rhel8/8.9/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/appstream/debug',
      'content/dist/rhel8/8.9/x86_64/appstream/os',
      'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/baseos/debug',
      'content/dist/rhel8/8.9/x86_64/baseos/os',
      'content/dist/rhel8/8.9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/appstream/debug',
      'content/dist/rhel8/8/s390x/appstream/os',
      'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'lemon-3.26.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sqlite-3.26.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sqlite-devel-3.26.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sqlite-doc-3.26.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sqlite-libs-3.26.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / sqlite / sqlite-devel / sqlite-doc / sqlite-libs');
}
