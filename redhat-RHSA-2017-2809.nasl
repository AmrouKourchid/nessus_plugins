#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2809. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103527);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2014-9970",
    "CVE-2015-6644",
    "CVE-2017-2582",
    "CVE-2017-5645",
    "CVE-2017-7536"
  );
  script_xref(name:"RHSA", value:"2017:2809");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform (RHSA-2017:2809)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2809 advisory.

    Red Hat JBoss Enterprise Application Platform is a platform for Java applications based on the JBoss
    Application Server.

    This release of Red Hat JBoss Enterprise Application Platform 7.0.8 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.0.7, and includes bug fixes and enhancements, which are documented
    in the Release Notes document linked to in the References.

    Security Fix(es):

    * It was found that when using remote logging with log4j socket server the log4j server would deserialize
    any log event received via TCP or UDP. An attacker could use this flaw to send a specially crafted log
    event that, during deserialization, would execute arbitrary code in the context of the logger application.
    (CVE-2017-5645)

    * A vulnerability was found in Jasypt that would allow an attacker to perform a timing attack on password
    hash comparison. (CVE-2014-9970)

    * It was found that an information disclosure flaw in Bouncy Castle could enable a local malicious
    application to gain access to user's private information. (CVE-2015-6644)

    * It was found that while parsing the SAML messages the StaxParserUtil class of Picketlink replaces
    special strings for obtaining attribute values with system property. This could allow an attacker to
    determine values of system properties at the attacked system by formatting the SAML request ID field to be
    the chosen system property which could be obtained in the InResponseTo field in the response.
    (CVE-2017-2582)

    * It was found that when the security manager's reflective permissions, which allows it to access the
    private members of the class, are granted to Hibernate Validator, a potential privilege escalation can
    occur. By allowing the calling code to access those private members without the permission an attacker may
    be able to validate an invalid instance and access the private member value via
    ConstraintViolation#getInvalidValue(). (CVE-2017-7536)

    The CVE-2017-2582 issue was discovered by Hynek Mlnarik (Red Hat) and the CVE-2017-7536 issue was
    discovered by Gunnar Morling (Red Hat).

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en/red-hat-jboss-enterprise-application-platform/version-7.0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e59ec4c");
  # https://access.redhat.com/documentation/en/red-hat-jboss-enterprise-application-platform/version-7.0/installation-guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d5922b5");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_2809.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c417326");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1410481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1443635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1444015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1455566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1465573");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-11484");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform package based on the guidance in RHSA-2017:2809.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 201, 385, 502);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jasypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jms-api_2.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-artemis-native-1.1.0-13.redhat_4.ep7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-artemis-native-1.1.0-13.redhat_4.ep7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-artemis-native-wildfly-1.1.0-13.redhat_4.ep7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-artemis-native-wildfly-1.1.0-13.redhat_4.ep7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-bouncycastle-1.56.0-3.redhat_2.2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-bouncycastle-mail-1.56.0-3.redhat_2.2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-bouncycastle-pkix-1.56.0-3.redhat_2.2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-bouncycastle-prov-1.56.0-3.redhat_2.2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-validator-5.2.5-2.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-validator-cdi-5.2.5-2.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jasypt-1.9.2-2.redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-jms-api_2.0_spec-1.0.1-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-logmanager-2.0.7-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-appclient-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-common-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-ear-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-ejb-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-metadata-web-10.0.2-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-remote-naming-2.0.5-1.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-remoting-4.0.24-1.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-log4j-jboss-logmanager-1.1.4-2.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-api-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-bindings-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-common-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-config-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-federation-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-api-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-impl-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-9.SP8_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-undertow-1.3.31-1.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-7.0.8-4.GA_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-javadocs-7.0.8-1.GA_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-modules-7.0.8-4.GA_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-artemis-native / eap7-artemis-native-wildfly / etc');
}
