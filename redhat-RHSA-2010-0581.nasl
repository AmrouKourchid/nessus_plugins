#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0581. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210145);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2010-2227");
  script_xref(name:"RHSA", value:"2010:0581");

  script_name(english:"RHEL 5 : tomcat5 and tomcat6 (RHSA-2010:0581)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for tomcat5 / tomcat6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2010:0581 advisory.

    Apache Tomcat is a servlet container for the Java Servlet and JavaServer
    Pages (JSP) technologies.

    A flaw was found in the way Tomcat handled the Transfer-Encoding header in
    HTTP requests. A specially-crafted HTTP request could prevent Tomcat from
    sending replies, or cause Tomcat to return truncated replies, or replies
    containing data related to the requests of other users, for all subsequent
    HTTP requests. (CVE-2010-2227)

    Users of Tomcat should upgrade to these updated packages, which contain a
    backported patch to resolve this issue. Tomcat must be restarted for this
    update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=612799");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0581.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14099d4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0581");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL tomcat5 / tomcat6 packages based on the guidance in RHSA-2010:0581.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbews/1/os',
      'content/dist/rhel/server/5/5Server/i386/jbews/1/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/1/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat5-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-admin-webapps-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-common-lib-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-eclipse-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-javadoc-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-javadoc-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-parent-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-server-lib-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-javadoc-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-webapps-5.5.28-9.patch_01.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-1.0-api-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.24-7.patch_01.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc');
}
