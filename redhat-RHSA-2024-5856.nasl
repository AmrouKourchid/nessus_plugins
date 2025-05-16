#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5856. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206210);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-10086",
    "CVE-2019-10174",
    "CVE-2019-12384",
    "CVE-2019-14379",
    "CVE-2019-14843",
    "CVE-2019-14888",
    "CVE-2019-16869",
    "CVE-2019-17531",
    "CVE-2019-20444",
    "CVE-2019-20445",
    "CVE-2020-1710",
    "CVE-2020-1745",
    "CVE-2020-1757",
    "CVE-2021-4104",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307"
  );
  script_xref(name:"RHSA", value:"2024:5856");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.1.7 on RHEL 7 (RHSA-2024:5856)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.1.7
on RHEL 7.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:5856 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 7.1.7 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 7.1.6, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 7.1.7 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * undertow: EAP: field-name is not parsed in accordance to RFC7230 [eap-7.1.z] (CVE-2020-1710)

    * commons-beanutils: apache-commons-beanutils: does not suppresses the class property in PropertyUtilsBean
    by default [eap-7.1.z] (CVE-2019-10086)

    * log4j: Remote code execution in Log4j 1.x when application is configured to use JMSSink [eap-7.1.z]
    (CVE-2022-23302)

    * jackson-databind: default typing mishandling leading to remote code execution [eap-7.1.z]
    (CVE-2019-14379)

    * undertow: HTTP/2: flood using HEADERS frames results in unbounded memory growth [eap-7.1.z]
    (CVE-2019-9514)

    * undertow: AJP File Read/Inclusion Vulnerability [eap-7.1.z] (CVE-2020-1745)

    * undertow: HTTP/2: large amount of data requests leads to denial of service [eap-7.1.z] (CVE-2019-9511)

    * undertow: servletPath in normalized incorrectly leading to dangerous application mapping which could
    result in security bypass [eap-7.1.z] (CVE-2020-1757)

    * undertow: possible Denial Of Service (DOS) in Undertow HTTP server listening on HTTPS [eap-7.1.z]
    (CVE-2019-14888)

    * log4j: Unsafe deserialization flaw in Chainsaw log viewer [eap-7.1.z] (CVE-2022-23307)

    * netty: HttpObjectDecoder.java allows Content-Length header to accompanied by second Content-Length
    header [eap-7.1.z] (CVE-2019-20445)

    * log4j: Remote code execution in Log4j 1.x when application is configured to use JMSAppender [eap-7.1.z]
    (CVE-2021-4104)

    * undertow: HTTP/2: flood using SETTINGS frames results in unbounded memory growth [eap-7.1.z]
    (CVE-2019-9515)

    * infinispan-core: infinispan: invokeAccessibly method from ReflectionUtil class allows to invoke private
    methods [eap-7.1.z] (CVE-2019-10174)

    * log4j: SQL injection in Log4j 1.x when application is configured to use JDBCAppender [eap-7.1.z]
    (CVE-2022-23305)

    * jackson-databind: failure to block the logback-core class from polymorphic deserialization leading to
    remote code execution [eap-7.1.z] (CVE-2019-12384)

    * wildfly-security-manager: security manager authorization bypass (CVE-2019-14843)

    * HTTP/2: flood using PING frames results in unbounded memory growth (CVE-2019-9512)

    * netty: HTTP request smuggling by mishandled whitespace before the colon in HTTP headers (CVE-2019-16869)

    * jackson-databind: Serialization gadgets in org.apache.log4j.receivers.db.* (CVE-2019-17531)

    * netty: HTTP request smuggling (CVE-2019-20444)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/7.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2684bd9c");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/7.1/html-single/installation_guide/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?690e43fa");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1725807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1737517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1741860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1752770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1752980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1758619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1767483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1772464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1775293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1793970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1807305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041967");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24826");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5856.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fe8ac9b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5856");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.1.7 on RHEL 7 package based on the guidance in
RHSA-2024:5856.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 89, 113, 200, 285, 400, 444, 470, 502, 592);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/debug',
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/os',
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-apache-commons-beanutils-1.9.4-1.redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10086', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-cachestore-jdbc-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-cachestore-remote-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-client-hotrod-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-commons-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-infinispan-core-8.2.11-1.SP2_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-10174', 'CVE-2020-1710']},
      {'reference':'eap7-jackson-databind-2.8.11.5-1.redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-12384', 'CVE-2019-14379', 'CVE-2019-17531', 'CVE-2020-1710']},
      {'reference':'eap7-log4j-jboss-logmanager-1.2.2-1.Final_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2020-1710', 'CVE-2021-4104', 'CVE-2022-23302', 'CVE-2022-23305', 'CVE-2022-23307']},
      {'reference':'eap7-netty-4.1.45-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-16869', 'CVE-2019-20444', 'CVE-2019-20445', 'CVE-2020-1710']},
      {'reference':'eap7-netty-all-4.1.45-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-16869', 'CVE-2019-20444', 'CVE-2019-20445', 'CVE-2020-1710']},
      {'reference':'eap7-undertow-1.4.18-12.SP12_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-14888', 'CVE-2020-1710', 'CVE-2020-1745', 'CVE-2020-1757']},
      {'reference':'eap7-wildfly-7.1.7-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-14843', 'CVE-2020-1710']},
      {'reference':'eap7-wildfly-elytron-1.1.13-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2020-1710']},
      {'reference':'eap7-wildfly-modules-7.1.7-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-9511', 'CVE-2019-9512', 'CVE-2019-9514', 'CVE-2019-9515', 'CVE-2019-14843', 'CVE-2020-1710']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-commons-beanutils / eap7-infinispan / etc');
}
