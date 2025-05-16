#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1622. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85441);
  script_version("2.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2014-0230", "CVE-2014-7810");
  script_xref(name:"RHSA", value:"2015:1622");

  script_name(english:"RHEL 5 / 6 / 7 : Red Hat JBoss Web Server 2.1.0 tomcat (RHSA-2015:1622)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Web Server 2.1.0 tomcat.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 / 7 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2015:1622 advisory.

    Red Hat JBoss Web Server is a fully integrated and certified set of
    components for hosting Java web applications. It is comprised of the Apache
    HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat Connector
    (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and the Tomcat
    Native library.

    It was found that the expression language resolver evaluated expressions
    within a privileged code section. A malicious web application could use
    this flaw to bypass security manager protections. (CVE-2014-7810)

    It was found that Tomcat would keep connections open after processing
    requests with a large enough request body. A remote attacker could
    potentially use this flaw to exhaust the pool of available connections and
    preventing further, legitimate connections to the Tomcat server to be made.
    (CVE-2014-0230)

    All users of Red Hat JBoss Web Server 2.1.0 as provided from the Red Hat
    Customer Portal are advised to apply this update. The Red Hat JBoss Web
    Server process must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_1622.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35ecd97b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1622");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1222573");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Web Server 2.1.0 tomcat package based on the guidance in RHSA-2015:1622.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(770);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-maven-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-maven-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbews/2/os',
      'content/dist/rhel/server/5/5Server/i386/jbews/2/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/2/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat6-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-maven-devel-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-15_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-maven-devel-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-19_patch_04.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbews/2/debug',
      'content/dist/rhel/server/6/6Server/i386/jbews/2/os',
      'content/dist/rhel/server/6/6Server/i386/jbews/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbews/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbews/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbews/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat6-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-maven-devel-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-15_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-maven-devel-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-19_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat6-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-maven-devel-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-15_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-maven-devel-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-20_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc');
}
