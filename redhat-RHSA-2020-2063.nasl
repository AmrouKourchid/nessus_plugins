##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2063. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136479);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2018-14371", "CVE-2019-10174");
  script_xref(name:"RHSA", value:"2020:2063");

  script_name(english:"RHEL 6 / 7 / 8 : Red Hat JBoss Enterprise Application Platform 7.2 (RHSA-2020:2063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 / 8 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2020:2063 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This asynchronous patch is a security update for the Infinispan package in Red Hat JBoss Enterprise
    Application Platform 7.2 for Red Hat Enterprise Linux 6, 7, and 8.

    Security Fix(es):

    * infinispan-core: infinispan: invokeAccessibly method from ReflectionUtil class allows to invoke private
    methods (CVE-2019-10174)

    * jsf-impl: mojarra: Path traversal in ResourceManager.java:getLocalePrefix() via the loc parameter
    (CVE-2018-14371)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, see the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_2063.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23793c5e");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad39889");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.2/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdc49160");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1607709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703469");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.2 package based on the guidance in RHSA-2020:2063.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10174");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 470);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbeap/7.2/debug',
      'content/dist/layered/rhel8/x86_64/jbeap/7.2/os',
      'content/dist/layered/rhel8/x86_64/jbeap/7.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-glassfish-jsf-2.3.5-11.SP3_redhat_00009.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-jdbc-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-remote-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-client-hotrod-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-commons-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-core-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-9.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-glassfish-jsf-2.3.5-11.SP3_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-jdbc-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-remote-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-client-hotrod-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-commons-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-core-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-9.3.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-glassfish-jsf-2.3.5-11.SP3_redhat_00009.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-jdbc-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-cachestore-remote-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-client-hotrod-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-commons-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-core-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-9.3.9-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-glassfish-jsf / eap7-infinispan / etc');
}
