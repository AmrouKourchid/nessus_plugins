#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1297. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159664);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-4104",
    "CVE-2021-44832",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307"
  );
  script_xref(name:"RHSA", value:"2022:1297");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"IAVA", value:"2022-A-0060");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.4 (RHSA-2022:1297)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.4.4.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2022:1297 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This release of Red Hat JBoss Enterprise Application Platform 7.4.4 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.4.3 and includes bug fixes and enhancements. See the Red Hat JBoss
    Enterprise Application Platform 7.4.4 Release Notes for information about the most significant bug fixes
    and enhancements included in this release.

    Security Fix(es):

    * log4j: SQL injection in Log4j 1.x when application is configured to use JDBCAppender (CVE-2022-23305)

    * log4j: Unsafe deserialization flaw in Chainsaw log viewer (CVE-2022-23307)

    * log4j: Remote code execution in Log4j 1.x when application is configured to use JMSAppender
    (CVE-2021-4104)

    * log4j-core: remote code execution via JDBC Appender (CVE-2021-44832)

    * log4j-core: DoS in log4j 2.x with thread context message pattern and context lookup pattern (incomplete
    fix for CVE-2021-44228) (CVE-2021-45046)

    * log4j-core: DoS in log4j 2.x with Thread Context Map (MDC) input data contains a recursive lookup and
    context lookup pattern (CVE-2021-45105)

    * log4j: Remote code execution in Log4j 1.x when application is configured to use JMSSink (CVE-2022-23302)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_1297.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfde75a2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2032580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2035951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041967");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22105");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22385");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22731");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22738");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22819");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22839");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22864");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22900");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22904");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22911");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22912");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22913");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22935");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22945");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22973");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23038");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23040");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23045");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23101");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23105");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23143");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23177");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23323");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23373");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23374");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23375");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.4.4 package based on the guidance in RHSA-2022:1297.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 89, 400, 502, 674);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/debug',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/os',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-log4j-2.17.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-log4j');
}
