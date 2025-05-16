#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0236. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64467);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2012-1541",
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0430",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57697,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57720,
    57722,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731
  );
  script_xref(name:"RHSA", value:"2013:0236");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-sun (RHSA-2013:0236)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.6.0-sun.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2013:0236 advisory.

    Oracle Java SE version 6 includes the Oracle Java Runtime Environment and
    the Oracle Java Software Development Kit.

    This update fixes several vulnerabilities in the Oracle Java Runtime
    Environment and the Oracle Java Software Development Kit. Further
    information about these flaws can be found on the Oracle Java SE Critical
    Patch Update Advisory page, listed in the References section.
    (CVE-2012-1541, CVE-2012-3213, CVE-2012-3342, CVE-2013-0351, CVE-2013-0409,
    CVE-2013-0419, CVE-2013-0423, CVE-2013-0424, CVE-2013-0425, CVE-2013-0426,
    CVE-2013-0427, CVE-2013-0428, CVE-2013-0429, CVE-2013-0430, CVE-2013-0432,
    CVE-2013-0433, CVE-2013-0434, CVE-2013-0435, CVE-2013-0438, CVE-2013-0440,
    CVE-2013-0441, CVE-2013-0442, CVE-2013-0443, CVE-2013-0445, CVE-2013-0446,
    CVE-2013-0450, CVE-2013-1473, CVE-2013-1475, CVE-2013-1476, CVE-2013-1478,
    CVE-2013-1480, CVE-2013-1481)

    All users of java-1.6.0-sun are advised to upgrade to these updated
    packages, which provide Oracle Java 6 Update 39. All running instances of
    Oracle Java must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a915dbbd");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0236");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=859140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=860652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907460");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_0236.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50b85adf");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.6.0-sun package based on the guidance in RHSA-2013:0236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1481");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-0433");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/supplementary/debug',
      'content/dist/rhel/client/6/6Client/i386/supplementary/os',
      'content/dist/rhel/client/6/6Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/os',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/supplementary/debug',
      'content/dist/rhel/server/6/6Server/i386/supplementary/os',
      'content/dist/rhel/server/6/6Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/os',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-sun-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-demo-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-demo-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-devel-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-devel-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-jdbc-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-jdbc-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-plugin-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-plugin-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-src-1.6.0.39-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-src-1.6.0.39-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/supplementary/debug',
      'content/dist/rhel/server/5/5Server/i386/supplementary/os',
      'content/dist/rhel/server/5/5Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/os',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-sun-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-demo-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-demo-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-devel-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-devel-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-jdbc-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-jdbc-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-plugin-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-plugin-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-src-1.6.0.39-1jpp.4.el5_9', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-sun-src-1.6.0.39-1jpp.4.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.6.0-sun / java-1.6.0-sun-demo / java-1.6.0-sun-devel / etc');
}
