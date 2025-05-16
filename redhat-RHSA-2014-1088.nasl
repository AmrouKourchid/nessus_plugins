#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1088. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77357);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2013-4590",
    "CVE-2014-0118",
    "CVE-2014-0119",
    "CVE-2014-0226",
    "CVE-2014-0227",
    "CVE-2014-0231"
  );
  script_xref(name:"RHSA", value:"2014:1088");

  script_name(english:"RHEL 5 : Red Hat JBoss Web Server 2.1.0 update (Important) (RHSA-2014:1088)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1088 advisory.

    Red Hat JBoss Web Server is a fully integrated and certified set of
    components for hosting Java web applications. It is comprised of the Apache
    HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat Connector
    (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and the Tomcat
    Native library.

    This release serves as a replacement for Red Hat JBoss Web Server 2.0.1,
    and includes several bug fixes. Refer to the Red Hat JBoss Web Server 2.1.0
    Release Notes, linked to in the References section, for information on the
    most significant of these changes.

    The following security issues are also fixed with this release:

    A race condition flaw, leading to heap-based buffer overflows, was found in
    the mod_status httpd module. A remote attacker able to access a status page
    served by mod_status on a server using a threaded Multi-Processing Module
    (MPM) could send a specially crafted request that would cause the httpd
    child process to crash or, possibly, allow the attacker to execute
    arbitrary code with the privileges of the apache user. (CVE-2014-0226)

    A denial of service flaw was found in the way httpd's mod_deflate module
    handled request body decompression (configured via the DEFLATE input
    filter). A remote attacker able to send a request whose body would be
    decompressed could use this flaw to consume an excessive amount of system
    memory and CPU on the target system. (CVE-2014-0118)

    A denial of service flaw was found in the way httpd's mod_cgid module
    executed CGI scripts that did not read data from the standard input.
    A remote attacker could submit a specially crafted request that would cause
    the httpd child process to hang indefinitely. (CVE-2014-0231)

    It was found that several application-provided XML files, such as web.xml,
    content.xml, *.tld, *.tagx, and *.jspx, resolved external entities,
    permitting XML External Entity (XXE) attacks. An attacker able to deploy
    malicious applications to Tomcat could use this flaw to circumvent security
    restrictions set by the JSM, and gain access to sensitive information on
    the system. Note that this flaw only affected deployments in which Tomcat
    is running applications from untrusted sources, such as in a shared hosting
    environment. (CVE-2013-4590)

    It was found that, in certain circumstances, it was possible for a
    malicious web application to replace the XML parsers used by Tomcat to
    process XSLTs for the default servlet, JSP documents, tag library
    descriptors (TLDs), and tag plug-in configuration files. The injected XML
    parser(s) could then bypass the limits imposed on XML external entities
    and/or gain access to the XML files processed for other web applications
    deployed on the same Tomcat instance. (CVE-2014-0119)

    All users of Red Hat JBoss Web Server 2.0.1 on Red Hat Enterprise Linux 5
    are advised to upgrade to Red Hat JBoss Web Server 2.1.0. The JBoss server
    process must be restarted for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1088.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08ece136");
  # https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Web_Server/2.1/html/2.1.0_Release_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ecc67b2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1069911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1102038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1120596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1120601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1120603");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0226");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(122, 400, 470, 611);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections-tomcat-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-jsvc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-tomcat-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-c3p0-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:storeconfig-tc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:storeconfig-tc7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbews/2/os',
      'content/dist/rhel/server/5/5Server/i386/jbews/2/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/2/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'antlr-eap6-2.7.7-17.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'apache-commons-collections-eap6-3.2.1-15.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'apache-commons-collections-tomcat-eap6-3.2.1-15.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'apache-commons-daemon-eap6-1.0.15-5.redhat_1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'apache-commons-daemon-jsvc-eap6-1.0.15-6.redhat_2.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'apache-commons-daemon-jsvc-eap6-1.0.15-6.redhat_2.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'apache-commons-pool-eap6-1.6-7.redhat_6.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'apache-commons-pool-tomcat-eap6-1.6-7.redhat_6.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'dom4j-eap6-1.6.1-20.redhat_6.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ecj3-3.7.2-9.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate4-c3p0-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate4-core-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate4-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate4-entitymanager-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate4-envers-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate4-infinispan-eap6-4.2.14-3.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-tools-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-tools-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'javassist-eap6-3.18.1-1.GA_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-logging-3.1.4-1.GA_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-transaction-api_1.1_spec-1.0.1-12.Final_redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-1.2.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.2.9-3.Final_redhat_2.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.2.9-3.Final_redhat_2.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-tomcat6-1.2.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-tomcat7-1.2.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap22-1.2.40-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap22-1.2.40-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.40-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.40-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_rt-2.4.1-6.GA.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_rt-2.4.1-6.GA.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_snmp-2.4.1-13.GA.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_snmp-2.4.1-13.GA.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'storeconfig-tc6-0.0.1-7.Alpha3_redhat_12.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'storeconfig-tc7-0.0.1-7.Alpha3_redhat_12.5.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-2.1-api-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.41-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-admin-webapps-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-docs-webapp-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-el-2.2-api-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-javadoc-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-lib-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-log4j-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat7-webapps-7.0.54-6_patch_02.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'antlr-eap6 / apache-commons-collections-eap6 / etc');
}
