#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:10208. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/27");

  script_cve_id(
    "CVE-2020-7238",
    "CVE-2020-28052",
    "CVE-2022-23221",
    "CVE-2022-34169",
    "CVE-2022-41853",
    "CVE-2022-46364",
    "CVE-2023-3171",
    "CVE-2023-5685",
    "CVE-2023-26464",
    "CVE-2023-39410",
    "CVE-2024-28752",
    "CVE-2024-47561"
  );
  script_xref(name:"RHSA", value:"2024:10208");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.1.8 on RHEL 7 (RHSA-2024:10208)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.1.8
on RHEL 7.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:10208 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 7.1.8 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 7.1.7, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 7.1.8 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * bouncycastle: password bypass in OpenBSDBCrypt.checkPassword utility possible [eap-7.1.z]
    (CVE-2020-28052)

    * hsqldb: Untrusted input may lead to RCE attack [eap-7.1.z] (CVE-2022-41853)

    * cxf-core: Apache CXF SSRF Vulnerability using the Aegis databinding [eap-7.1.z] (CVE-2024-28752)

    * h2: Loading of custom classes from remote servers through JNDI [eap-7.1.z] (CVE-2022-23221)

    * CXF: Apache CXF: SSRF Vulnerability [eap-7.1.z] (CVE-2022-46364)

    * xalan: integer truncation issue in Xalan-J (JAXP, 8285407) [eap-7.1.z] (CVE-2022-34169)

    * log4j: log4j1-chainsaw, log4j1-socketappender: DoS via hashmap logging [eap-7.1.z] (CVE-2023-26464)

    * xnio: StackOverflowException when the chain of notifier states becomes problematically big [eap-7.1.z]
    (CVE-2023-5685)

    * server: eap-7: heap exhaustion via deserialization [eap-7.1.z] (CVE-2023-3171)

    * netty: HTTP Request Smuggling due to Transfer-Encoding whitespace mishandling [eap-7.1.z]
    (CVE-2020-7238)

    * avro: apache-avro: Apache Avro Java SDK: Memory when deserializing untrusted data in Avro Java SDK
    [eap-7.1.z] (CVE-2023-39410)

    * avro: apache-avro: Schema parsing may trigger Remote Code Execution (RCE) [eap-7.1.z] (CVE-2024-47561)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1796225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2108554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2182864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316116");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27708");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28086");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28130");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_10208.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e13e0e25");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10208");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.1.8 on RHEL 7 package based on the guidance in
RHSA-2024:10208.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23221");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(192, 287, 400, 444, 470, 502, 789, 918);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling-river");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xalan-j2");
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
      {'reference':'eap7-apache-cxf-3.1.16-3.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2022-46364', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-apache-cxf-rt-3.1.16-3.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2022-46364', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-apache-cxf-services-3.1.16-3.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2022-46364', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-apache-cxf-tools-3.1.16-3.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2022-46364', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-avro-1.7.6-2.redhat_00003.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-bouncycastle-1.68.0-1.redhat_00005.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2020-28052', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-bouncycastle-mail-1.68.0-1.redhat_00005.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2020-28052', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-bouncycastle-pkix-1.68.0-1.redhat_00005.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2020-28052', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-bouncycastle-prov-1.68.0-1.redhat_00005.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2020-28052', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-h2database-1.4.197-2.redhat_00005.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-23221', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-jackson-databind-2.8.11.6-1.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-jboss-marshalling-2.0.15-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-jboss-marshalling-river-2.0.15-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-jboss-xnio-base-3.5.10-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-wildfly-7.1.8-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-wildfly-modules-7.1.8-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']},
      {'reference':'eap7-xalan-j2-2.7.1-26.redhat_00015.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-7238', 'CVE-2022-34169', 'CVE-2022-41853', 'CVE-2023-3171', 'CVE-2023-5685', 'CVE-2023-26464', 'CVE-2023-39410', 'CVE-2024-28752', 'CVE-2024-47561']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-cxf / eap7-apache-cxf-rt / eap7-apache-cxf-services / etc');
}
