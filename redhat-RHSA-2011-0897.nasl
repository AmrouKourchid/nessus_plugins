#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0897. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193971);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id(
    "CVE-2010-1157",
    "CVE-2010-1452",
    "CVE-2010-1623",
    "CVE-2010-3718",
    "CVE-2010-4172",
    "CVE-2011-0013",
    "CVE-2011-0419",
    "CVE-2012-4557"
  );
  script_xref(name:"RHSA", value:"2011:0897");

  script_name(english:"RHEL 5 / 6 : JBoss Enterprise Web Server 1.0.2 update (Moderate) (RHSA-2011:0897)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:0897 advisory.

  - tomcat: information disclosure in authentication headers (CVE-2010-1157)

  - httpd mod_cache, mod_dav: DoS (httpd child process crash) by parsing URI structure with missing path
    segments (CVE-2010-1452)

  - apr-util: high memory consumption in apr_brigade_split_line() (CVE-2010-1623)

  - tomcat: file permission bypass flaw (CVE-2010-3718)

  - tomcat: cross-site-scripting vulnerability in the manager application (CVE-2010-4172)

  - tomcat: XSS vulnerability in HTML Manager interface (CVE-2011-0013)

  - apr: unconstrained recursion in apr_fnmatch (CVE-2011-0419)

  - httpd: mod_proxy_ajp worker moved to error state when timeout exceeded (CVE-2012-4557)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Web_Server/1.0/html-single/Release_Notes_1.0.2/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82cadf44");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=585331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=618189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=656246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=675786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=675792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=677655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=677657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=677659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=703390");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2011/rhsa-2011_0897.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e490fd7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0897");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-nodeps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ant-trax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-chain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-daemon-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-digester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-fileupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-launcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-modeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-taglibs-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mx4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:struts12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-jkstatus-ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.1-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.2-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.3-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which11");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbews/1/os',
      'content/dist/rhel/server/5/5Server/i386/jbews/1/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/1/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbews/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ant-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-antlr-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-bcel-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-bsf-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-log4j-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-oro-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-regexp-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-resolver-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-commons-logging-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-javamail-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jdepend-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jmf-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jsch-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-junit-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-nodeps-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-scripts-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-swing-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-trax-1.7.1-13.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'antlr-2.7.7-7.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'cglib-2.2-5.1.1.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'dom4j-1.6.1-11.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ecj3-3.3.1.1-3.1.1.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'glassfish-jsf-1.2_13-3.1.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-3.3.2-1.4.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-annotations-3.4.0-3.2.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-annotations-javadoc-3.4.0-3.2.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-commons-annotations-3.1.0-1.8.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-commons-annotations-javadoc-3.1.0-1.8.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-1.0.2-3.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-javadoc-1.0.2-3.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-entitymanager-3.4.0-4.3.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-entitymanager-javadoc-3.4.0-4.3.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-javadoc-3.3.2-1.4.GA_CP04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.17-11.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.17-11.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.17-11.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.17-11.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.17-11.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.17-11.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-beanutils-1.8.0-4.1.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-chain-1.2-2.2.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-codec-1.3-9.2.1.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-collections-3.2.1-4.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-collections-tomcat5-3.2.1-4.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-1.0.5-1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-jsvc-1.0.5-1.4.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-jsvc-1.0.5-1.4.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-dbcp-1.2.1-16.4.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-dbcp-tomcat5-1.2.1-16.4.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-digester-1.8.1-8.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-fileupload-1.1.1-7.4.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-httpclient-3.1-1.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-io-1.4-1.3.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-1.1.1-0.4.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-jboss-1.1-10.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-tomcat6-1.1.1-0.4.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-pool-1.3-11.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-pool-tomcat5-1.3-11.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-validator-1.3.1-7.5.2.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-oro-2.0.8-3.3.2.1.1.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-taglibs-standard-1.1.1-9.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'javassist-3.12.0-1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-core-2.2.17-1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-logging-jdk-2.1.2-1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-logging-spi-2.1.2-1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-javaee-5.0.1-2.9.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-javaee-poms-5.0.1-2.9.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-jms-1.1-api-5.0.1-2.9.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jcommon-1.0.16-1.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jfreechart-1.0.13-2.3.2.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-demo-1.0.10-2.1.GA_CP01.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-jbossas-1.0.10-2.1.GA_CP01.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-jbossweb2-1.0.10-2.1.GA_CP01.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.0.10-2.1.GA_CP01.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.0.10-2.1.GA_CP01.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-tomcat6-1.0.10-2.1.GA_CP01.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.31-1.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.31-1.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.17-11.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.17-11.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'objectweb-asm-3.1-5.3.1.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'struts12-1.2.9-3.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-jkstatus-ant-1.2.31-2.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.20-2.1.ep5.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.20-2.1.ep5.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-admin-webapps-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-common-lib-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-eclipse-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-javadoc-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-javadoc-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-parent-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-server-lib-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-javadoc-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-webapps-5.5.33-16_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-1.0-api-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.32-15.1_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xalan-j2-2.7.1-5.3_patch_04.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xerces-j2-2.9.1-3.patch01.1.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-1.3.04-7.10.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-jaxp-1.2-apis-1.3.04-7.10.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-jaxp-1.3-apis-1.3.04-7.10.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-resolver12-1.3.04-7.10.jdk6.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbews/1/os',
      'content/dist/rhel/server/6/6Server/i386/jbews/1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbews/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbews/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ant-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-antlr-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-bcel-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-bsf-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-log4j-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-oro-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-regexp-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-apache-resolver-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-commons-logging-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-commons-net-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-javamail-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jdepend-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jmf-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-jsch-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-junit-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-nodeps-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-scripts-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-swing-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ant-trax-1.7.1-14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'antlr-2.7.7-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'cglib-2.2-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'dom4j-1.6.1-11.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'ecj3-3.3.1.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'glassfish-jsf-1.2_13-3.1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-3.3.2-1.8.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-annotations-3.4.0-3.5.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-annotations-javadoc-3.4.0-3.5.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-commons-annotations-3.1.0-1.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-commons-annotations-javadoc-3.1.0-1.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-1.0.2-3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-javadoc-1.0.2-3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'hibernate3-entitymanager-3.4.0-4.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-entitymanager-javadoc-3.4.0-4.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'hibernate3-javadoc-3.3.2-1.8.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.17-11.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-2.2.17-11.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.17-11.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-devel-2.2.17-11.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.17-11.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-manual-2.2.17-11.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-tools-2.2.17-11.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'httpd-tools-2.2.17-11.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-beanutils-1.8.0-9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-chain-1.2-2.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-codec-1.3-12.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-collections-3.2.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-collections-tomcat5-3.2.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-1.0.5-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-jsvc-1.0.5-1.4.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-daemon-jsvc-1.0.5-1.4.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-dbcp-1.2.1-16.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-dbcp-tomcat5-1.2.1-16.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-digester-1.8.1-8.1.1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-fileupload-1.1.1-7.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-httpclient-3.1-1.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-io-1.4-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-1.1.1-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-jboss-1.1-10.2.2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-logging-tomcat6-1.1.1-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-pool-1.3-15.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-pool-tomcat5-1.3-15.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-commons-validator-1.3.1-7.5.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-oro-2.0.8-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jakarta-taglibs-standard-1.1.1-12.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'javassist-3.12.0-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-core-2.2.17-1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-logging-jdk-2.1.2-1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-common-logging-spi-2.1.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-javaee-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-javaee-poms-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-jms-1.1-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jcommon-1.0.16-1.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'jfreechart-1.0.13-2.3.2.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-demo-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-jbossas-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-jbossweb2-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_cluster-tomcat6-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.31-1.1.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_jk-manual-1.2.31-1.1.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.17-11.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'mod_ssl-2.2.17-11.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'tomcat'},
      {'reference':'objectweb-asm31-3.1-12.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'struts12-1.2.9-3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-jkstatus-ant-1.2.31-2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.20-2.1.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat-native-1.1.20-2.1.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-admin-webapps-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-common-lib-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-eclipse-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jasper-javadoc-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-jsp-2.0-api-javadoc-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-parent-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-server-lib-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-servlet-2.4-api-javadoc-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat5-webapps-5.5.33-15_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-admin-webapps-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-docs-webapp-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-el-1.0-api-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-javadoc-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-jsp-2.1-api-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-lib-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-log4j-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-servlet-2.5-api-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'tomcat6-webapps-6.0.32-14_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xalan-j2-2.7.1-5.3_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xerces-j2-2.9.1-8.patch01.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-jaxp-1.1-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-jaxp-1.2-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-jaxp-1.3-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-resolver10-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-resolver11-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-resolver12-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-which10-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'},
      {'reference':'xml-commons-which11-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'tomcat'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ant / ant-antlr / ant-apache-bcel / ant-apache-bsf / etc');
}
