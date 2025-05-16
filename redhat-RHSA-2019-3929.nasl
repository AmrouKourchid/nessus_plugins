#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3929. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131214);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2018-5407",
    "CVE-2019-0199",
    "CVE-2019-0221",
    "CVE-2019-0232",
    "CVE-2019-1559",
    "CVE-2019-10072"
  );
  script_xref(name:"RHSA", value:"2019:3929");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 6 / 7 / 8 : Red Hat JBoss Web Server 5.2 security  (Important) (RHSA-2019:3929)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 / 8 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2019:3929 advisory.

    Red Hat JBoss Web Server is a fully integrated and certified set of components for hosting Java web
    applications. It is comprised of the Apache Tomcat Servlet container, JBoss HTTP Connector (mod_cluster),
    the PicketLink Vault extension for Apache Tomcat, and the Tomcat Native library.

    This release of Red Hat JBoss Web Server 5.2 serves as a replacement for Red Hat JBoss Web Server 5.1, and
    includes bug fixes, enhancements, and component upgrades, which are documented in the Release Notes,
    linked to in the References.

    Security Fix(es):

    * openssl: Side-channel vulnerability on SMT/Hyper-Threading architectures (PortSmash) (CVE-2018-5407)

    * openssl: 0-byte record padding oracle (CVE-2019-1559)

    * tomcat: HTTP/2 connection window exhaustion on write, incomplete fix of CVE-2019-0199 (CVE-2019-10072)

    * tomcat: XSS in SSI printenv (CVE-2019-0221)

    * tomcat: Apache Tomcat HTTP/2 DoS (CVE-2019-0199)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_3929.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8c8a7fa");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_web_server/5.2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd5659a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3929");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1645695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1683804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1693325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1723708");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0232");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 200, 325, 400, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-javapackages-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-mod_cluster-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-python-javapackages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-vault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-vault-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jws5-tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jws/5/debug',
      'content/dist/layered/rhel8/x86_64/jws/5/os',
      'content/dist/layered/rhel8/x86_64/jws/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jws5-ecj-4.12.0-1.redhat_1.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-javapackages-tools-3.4.1-5.15.11.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-python-javapackages-3.4.1-5.15.11.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-native-1.2.21-34.redhat_34.el8jws', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el8jws', 'release':'8', 'el_string':'el8jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jws/5/debug',
      'content/dist/rhel/server/6/6Server/i386/jws/5/os',
      'content/dist/rhel/server/6/6Server/i386/jws/5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jws/5/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jws/5/os',
      'content/dist/rhel/server/6/6Server/x86_64/jws/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jws5-ecj-4.12.0-1.redhat_1.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-javapackages-tools-3.4.1-5.15.11.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-python-javapackages-3.4.1-5.15.11.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-native-1.2.21-34.redhat_34.el6jws', 'cpu':'i686', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-native-1.2.21-34.redhat_34.el6jws', 'cpu':'x86_64', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el6jws', 'release':'6', 'el_string':'el6jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/os',
      'content/dist/rhel/server/7/7Server/x86_64/jws/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jws5-ecj-4.12.0-1.redhat_1.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-javapackages-tools-3.4.1-5.15.11.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-jboss-logging-3.3.2-1.Final_redhat_00001.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-1.4.1-1.Final_redhat_00001.2.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-mod_cluster-tomcat-1.4.1-1.Final_redhat_00001.2.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-python-javapackages-3.4.1-5.15.11.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-admin-webapps-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-docs-webapp-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-el-3.0-api-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-javadoc-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-jsp-2.3-api-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-lib-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-native-1.2.21-34.redhat_34.el7jws', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-selinux-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-servlet-4.0-api-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-1.1.8-1.Final_redhat_1.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-vault-javadoc-1.1.8-1.Final_redhat_1.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'},
      {'reference':'jws5-tomcat-webapps-9.0.21-10.redhat_4.1.el7jws', 'release':'7', 'el_string':'el7jws', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jws5-ecj / jws5-javapackages-tools / jws5-jboss-logging / etc');
}
