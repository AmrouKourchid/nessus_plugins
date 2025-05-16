#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:2026. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(217006);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_cve_id("CVE-2024-10234");
  script_xref(name:"RHSA", value:"2025:2026");

  script_name(english:"RHEL 9 : Red Hat JBoss Enterprise Application Platform 8.0.6 (RHSA-2025:2026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat JBoss Enterprise Application Platform 8.0.6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:2026 advisory.

    Red Hat JBoss Enterprise Application Platform 8 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 8.0.6 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 8.0.5, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 8.0.6 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * org.wildfly.core/wildfly-core-management-subsystem: Wildfly vulnerable to Cross-Site Scripting (XSS)
    [eap-8.0.z] (CVE-2024-10234)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/8.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?451267bf");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/7100706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2320848");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27765");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28389");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28402");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28774");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28836");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28845");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28880");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-29009");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_2026.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10df5948");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:2026");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 8.0.6 package based on the guidance in RHSA-2025:2026.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10234");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-artemis-wildfly-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-azure-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-eap-product-conf-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-eap-product-conf-wildfly-ee-feature-pack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-authentication-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-authorization-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-enterprise-cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-enterprise-concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-enterprise-concurrent-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-enterprise-lang-model");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-security-enterprise-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-servlet-jsp-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-javaewah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-aesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-common-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-el-api_5.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-iiop-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-invocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-msc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-remoting-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-stdio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-transaction-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jbossws-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-json-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-reactivex-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-slf4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-staxmapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xml-resolver");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/debug',
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/os',
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap8-artemis-wildfly-integration-2.0.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-azure-storage-8.6.6-5.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-eap-product-conf-parent-800.6.0-2.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-eap-product-conf-wildfly-ee-feature-pack-800.6.0-2.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-gnu-getopt-1.0.13-2.redhat_5.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-h2database-2.1.214-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-hal-console-3.6.23-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-hibernate-commons-annotations-6.0.6-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jackson-coreutils-1.8.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-authentication-api-3.0.0-3.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-authorization-api-2.1.0-3.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-enterprise-cdi-api-4.0.1-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-enterprise-concurrent-3.0.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-enterprise-concurrent-api-3.0.2-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-enterprise-lang-model-4.0.1-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-security-enterprise-api-3.0.0-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jakarta-servlet-jsp-api-3.1.0-3.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-javaewah-1.1.13-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-aesh-2.4.0-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-common-beans-2.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-dmr-1.6.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-ejb3-ext-api-2.3.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-el-api_5.0_spec-4.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-genericjms-3.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-iiop-client-2.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-invocation-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-logmanager-2.1.19-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-msc-1.5.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-remoting-jmx-3.0.4-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-stdio-1.1.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-threads-2.4.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-transaction-spi-8.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jboss-vfs-3.3.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jbossws-api-3.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jbossws-common-5.1.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jbossws-cxf-7.3.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jbossws-spi-5.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jcip-annotations-1.0.0-2.redhat_8.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-json-patch-1.9.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-jul-to-slf4j-stub-1.0.1-2.Final_redhat_3.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-reactivex-rxjava2-2.2.21-2.redhat_00001.2.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-slf4j-jboss-logmanager-2.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-staxmapper-1.4.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-8.0.6-5.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-common-1.6.0-4.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-java-jdk11-8.0.6-5.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-java-jdk17-8.0.6-5.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-java-jdk21-8.0.6-5.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-wildfly-modules-8.0.6-5.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-woodstox-core-6.4.0-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-xml-commons-resolver-1.2.0-3.redhat_12.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'},
      {'reference':'eap8-xml-resolver-1.2.0-3.redhat_12.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap8-artemis-wildfly-integration / eap8-azure-storage / etc');
}
