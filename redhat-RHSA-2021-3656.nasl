#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3656. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153835);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2020-13936",
    "CVE-2021-3536",
    "CVE-2021-3597",
    "CVE-2021-3642",
    "CVE-2021-3644",
    "CVE-2021-3690",
    "CVE-2021-21295",
    "CVE-2021-21409",
    "CVE-2021-28170",
    "CVE-2021-29425"
  );
  script_xref(name:"RHSA", value:"2021:3656");
  script_xref(name:"IAVA", value:"2021-A-0347");
  script_xref(name:"IAVA", value:"2021-A-0392-S");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.4.1 security update on RHEL 7 (Important) (RHSA-2021:3656)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.4.1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:3656 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This release of Red Hat JBoss Enterprise Application Platform 7.4.1 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.4.0 and includes bug fixes and enhancements. See the Red Hat JBoss
    Enterprise Application Platform 7.4.1 Release Notes for information about the most significant bug fixes
    and enhancements included in this release.

    Security Fix(es):

    * velocity: arbitrary code execution when attacker is able to modify templates (CVE-2020-13936)

    * undertow: buffer leak on incoming websocket PONG message may lead to DoS (CVE-2021-3690)

    * undertow: HTTP2SourceChannel fails to write final frame under some circumstances may lead to DoS
    (CVE-2021-3597)

    * wildfly-elytron: possible timing attack in ScramServer (CVE-2021-3642)

    * netty: possible request smuggling in HTTP/2 due missing validation (CVE-2021-21295)

    * netty: Request smuggling via content-length header (CVE-2021-21409)

    * jakarta-el: ELParserTokenManager enables invalid EL expressions to be evaluate (CVE-2021-28170)

    * apache-commons-io: Limited path traversal in Apache Commons IO 2.2 to 2.6 (CVE-2021-29425)

    * wildfly: XSS via admin console when creating roles in domain mode (CVE-2021-3536)

    * wildfly-core: Invalid Sensitivity Classification of Vault Expression (CVE-2021-3644)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_3656.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?393fdc28");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1948001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1948752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1970930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1976052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1981407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1991299");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-18401");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21231");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21257");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21258");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21261");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21263");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21270");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21276");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21277");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21281");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21300");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21309");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21313");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21472");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21569");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21777");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21781");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21818");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21961");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-21978");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22009");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22084");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22088");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22160");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22209");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22318");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-22319");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.4.1 package based on the guidance in RHSA-2021:3656.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13936");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 22, 79, 94, 200, 203, 362, 401, 444);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jakarta-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-velocity-engine-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-apache-commons-io-2.10.0-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-29425']},
      {'reference':'eap7-jakarta-el-3.0.3-2.redhat_00006.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-28170']},
      {'reference':'eap7-netty-4.1.63-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-21295', 'CVE-2021-21409']},
      {'reference':'eap7-netty-all-4.1.63-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-21295', 'CVE-2021-21409']},
      {'reference':'eap7-undertow-2.2.9-2.SP1_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3597', 'CVE-2021-3690']},
      {'reference':'eap7-velocity-2.3.0-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-13936']},
      {'reference':'eap7-velocity-engine-core-2.3.0-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-13936']},
      {'reference':'eap7-wildfly-7.4.1-2.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3536', 'CVE-2021-3644']},
      {'reference':'eap7-wildfly-elytron-1.15.5-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3642']},
      {'reference':'eap7-wildfly-elytron-tool-1.15.5-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3642']},
      {'reference':'eap7-wildfly-java-jdk11-7.4.1-2.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3536', 'CVE-2021-3644']},
      {'reference':'eap7-wildfly-java-jdk8-7.4.1-2.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3536', 'CVE-2021-3644']},
      {'reference':'eap7-wildfly-javadocs-7.4.1-2.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3536', 'CVE-2021-3644']},
      {'reference':'eap7-wildfly-modules-7.4.1-2.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3536', 'CVE-2021-3644']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-commons-io / eap7-jakarta-el / eap7-netty / etc');
}
