#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0394. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40742);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2006-2426",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1107"
  );
  script_bugtraq_id(34240);
  script_xref(name:"RHSA", value:"2009:0394");

  script_name(english:"RHEL 5 : java-1.5.0-sun (RHSA-2009:0394)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.5.0-sun.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2009:0394 advisory.

    The Sun 1.5.0 Java release includes the Sun Java 5 Runtime Environment and
    the Sun Java 5 Software Development Kit.

    This update fixes several vulnerabilities in the Sun Java 5 Runtime
    Environment and the Sun Java 5 Software Development Kit. These
    vulnerabilities are summarized on the Advance notification of Security
    Updates for Java SE page from Sun Microsystems, listed in the References
    section. (CVE-2006-2426, CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
    CVE-2009-1096, CVE-2009-1098, CVE-2009-1099, CVE-2009-1100, CVE-2009-1103,
    CVE-2009-1104, CVE-2009-1107)

    Users of java-1.5.0-sun should upgrade to these updated packages, which
    correct these issues. All running instances of Sun Java must be restarted
    for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://blogs.sun.com/security/entry/advance_notification_of_security_updates4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?025abcaa");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2009/rhsa-2009_0394.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b395ca93");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2009:0394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=395481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492312");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.5.0-sun package based on the guidance in RHSA-2009:0394.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1096");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-1094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/os',
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/os',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.5.0-sun-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-1.5.0.18-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-demo-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-demo-1.5.0.18-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-devel-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-devel-1.5.0.18-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-jdbc-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-jdbc-1.5.0.18-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-plugin-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-src-1.5.0.18-1jpp.1.el5', 'cpu':'i586', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'java-1.5.0-sun-src-1.5.0.18-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.5.0-sun / java-1.5.0-sun-demo / java-1.5.0-sun-devel / etc');
}
