#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:0361. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214283);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id("CVE-2024-50379");
  script_xref(name:"RHSA", value:"2025:0361");

  script_name(english:"RHEL 7 / 8 / 9 : Red Hat JBoss Web Server 5.8.2 (RHSA-2025:0361)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat JBoss Web Server 5.8.2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 / 9 host has packages installed that are affected by a vulnerability as
referenced in the RHSA-2025:0361 advisory.

    Red Hat JBoss Web Server is a fully integrated and certified set of components for hosting Java web
    applications. It is comprised of the Apache Tomcat Servlet container, JBoss HTTP Connector (mod_cluster),
    the PicketLink Vault extension for Apache Tomcat, and the Tomcat Native library.

    This release of Red Hat JBoss Web Server 5.8.2 serves as a replacement for Red Hat JBoss Web Server 5.8.1.
    This release includes bug fixes, enhancements and component upgrades, which are documented in the Release
    Notes that are linked to in the References section.

    Security Fix(es):

    * tomcat: RCE due to TOCTOU issue in JSP compilation [jws-5] (CVE-2024-50379)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_web_server/5.8/html-single/red_hat_jboss_web_server_5.8_service_pack_2_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6048bc2d");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332817");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_0361.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1b0fcf1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:0361");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Web Server 5.8.2 package based on the guidance in RHSA-2025:0361.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(367);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-webapps");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jws/5/debug',
      'content/dist/layered/rhel8/x86_64/jws/5/os',
      'content/dist/layered/rhel8/x86_64/jws/5/source/SRPMS',
      'content/dist/middleware/jws/1.0/x86_64/os'
    ],
    'pkgs': [
      {'reference':'jws5-tomcat-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.87-6.redhat_00006.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/jws/5/debug',
      'content/dist/layered/rhel9/x86_64/jws/5/os',
      'content/dist/layered/rhel9/x86_64/jws/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jws5-tomcat-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.87-6.redhat_00006.1.el9jws', 'release':'9', 'el_string':'el9jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/os',
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jws5-tomcat-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-java-jdk11-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-java-jdk8-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.87-6.redhat_00006.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jws5-tomcat / jws5-tomcat-admin-webapps / jws5-tomcat-docs-webapp / etc');
}
