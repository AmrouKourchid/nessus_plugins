#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4591. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194233);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2023-30608", "CVE-2023-31047");
  script_xref(name:"RHSA", value:"2023:4591");

  script_name(english:"RHEL 8 : RHUI 4.5.0  - Security, Bug Fixes, and Enhancements (Moderate) (RHSA-2023:4591)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:4591 advisory.

    Red Hat Update Infrastructure (RHUI) offers a highly scalable, highly redundant framework that enables you
    to manage repositories and content. It also enables cloud providers to deliver content and updates to Red
    Hat Enterprise Linux (RHEL) instances.

    Security Fix(es):
    * Django: Potential bypass of validation when uploading multiple files using a single form field
    (CVE-2023-31047)

    * sqlparse: Parser contains a regular expression that is vulnerable to ReDOS (Regular Expression Denial of
    Service) (CVE-2023-30608)

    This RHUI update fixes the following bugs:

    * Previously, the `rhui-manager` command used the `logname` command to obtain the login name. However,
    when `rhui-manager` is run using the `rhui-repo-sync` cron job, a login name is not defined. Consequently,
    emails sent by the cron job contained the error message `logname: no login name`. With this update, `rhui-
    manager` does not obtain the login name using the `logname` command and the error message is no longer
    generated.

    * Previously, when an invalid repository ID was used with the `rhui-manager` command to synchronize or
    delete a repository, the command failed with following error:
    `An unexpected error has occurred during the last operation.`
    Additionally, a traceback was also logged.
    With this update, the error message has been improved and failure to run no longer logs a traceback.

    This RHUI update introduces the following enhancements:

    * With this update, the client configuration RPMs in `rhui-manager` prevent subscription manager from
    automatically enabling `yum` plugins. As a result, RHUI repository users will no longer see irrelevant
    messages from subscription manager. (BZ#1957871)

    * With this update, you can generate machine-readable files with the status of each RHUI repository. To
    use this feature, run the following command:
    `rhui-manager --non-interactive status --repo_json <output file>`
     (BZ#2079391)

    * With this update, the `rhui-manager` CLI command uses a variety of unique exit codes to indicate
    different types of errors. For example, if you attempt to add a Red Hat repository that has already been
    added, the command will exit with a status of 245. However, if you attempt to add a Red Hat repository
    that does not exist in the RHUI entitlement, the command will exit with a status of 246. For a complete
    list of codes, see the `/usr/lib/python3.6/site-packages/rhui/common/rhui_exit_codes.py` file.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_4591.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7da3c52c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2187903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2192565");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-217");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-263");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-356");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-395");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-424");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-430");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-75");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4591");
  script_set_attribute(attribute:"solution", value:
"Update the affected python39-django and / or python39-sqlparse packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31047");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-sqlparse");
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
      {'reference':'python39-django-3.2.19-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-31047']},
      {'reference':'python39-sqlparse-0.4.4-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-30608']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39-django / python39-sqlparse');
}
