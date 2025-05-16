#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2493. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(102692);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id(
    "CVE-2016-6304",
    "CVE-2016-8610",
    "CVE-2017-5647",
    "CVE-2017-5664"
  );
  script_xref(name:"RHSA", value:"2017:2493");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server 2 (RHSA-2017:2493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Web Server 2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2493 advisory.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS)
    protocols, as well as a full-strength general-purpose cryptography library.

    Apache Tomcat is a servlet container for the Java Servlet and JavaServer Pages (JSP) technologies.

    This release provides an update to OpenSSL and Tomcat 6/7 for Red Hat JBoss Web Server 2.1.2. The updates
    are documented in the Release Notes document linked to in the References.

    Users of Red Hat JBoss Web Server 2.1.2 should upgrade to these updated packages, which resolve several
    security issues.

    Security Fix(es):

    * A memory leak flaw was found in the way OpenSSL handled TLS status request extension data during session
    renegotiation. A remote attacker could cause a TLS server using OpenSSL to consume an excessive amount of
    memory and, possibly, exit unexpectedly after exhausting all available memory, if it enabled OCSP stapling
    support. (CVE-2016-6304)

    * A vulnerability was discovered in tomcat's handling of pipelined requests when Sendfile was used. If
    sendfile processing completed quickly, it was possible for the Processor to be added to the processor
    cache twice. This could lead to invalid responses or information disclosure. (CVE-2017-5647)

    * A vulnerability was discovered in the error page mechanism in Tomcat's DefaultServlet implementation. A
    crafted HTTP request could cause undesired side effects, possibly including the removal or replacement of
    the custom error page. (CVE-2017-5664)

    * A denial of service flaw was found in the way the TLS/SSL protocol defined processing of ALERT packets
    during a connection handshake. A remote attacker could use this flaw to make a TLS/SSL server consume an
    excessive amount of CPU and fail to accept connections from other clients. (CVE-2016-8610)

    Red Hat would like to thank the OpenSSL project for reporting CVE-2016-6304 and Shi Lei (Gear Team of
    Qihoo 360 Inc.) for reporting CVE-2016-8610. Upstream acknowledges Shi Lei (Gear Team of Qihoo 360 Inc.)
    as the original reporter of CVE-2016-6304.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_2493.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4076fc30");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3155411");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2493");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1377600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1384743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1441205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459158");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Web Server 2 package based on the guidance in RHSA-2017:2493.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 266, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
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
      {'reference':'jbcs-httpd24-openssl-1.0.2h-13.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-13.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-maven-devel-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-17_patch_04.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-maven-devel-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-25_patch_05.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbews/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-openssl-1.0.2h-13.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-maven-devel-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-17_patch_04.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-maven-devel-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-25_patch_05.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-openssl / jbcs-httpd24-openssl-devel / etc');
}
