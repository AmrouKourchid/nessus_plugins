#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0364. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122332);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2018-10934", "CVE-2018-14642", "CVE-2018-1000632");
  script_xref(name:"RHSA", value:"2019:0364");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 7.1.6 on RHEL 6 (RHSA-2019:0364)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.1.6
on RHEL 6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:0364 advisory.

    Red Hat JBoss Enterprise Application Platform is a platform for Java applications based on the JBoss
    Application Server.

    This release of Red Hat JBoss Enterprise Application Platform 7.1.6 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.1.5, and includes bug fixes and enhancements, which are documented
    in the Release Notes document linked to in the References.

    Security Fix(es):

    * wildfly-core: Cross-site scripting (XSS) in JBoss Management Console (CVE-2018-10934)

    * undertow: Infoleak in some circumstances where Undertow can serve data from a random buffer
    (CVE-2018-14642)

    * dom4j: XML Injection in Class: Element. Methods: addElement, addAttribute which can impact the integrity
    of XML documents (CVE-2018-1000632)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/?version=7.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ae1b122");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_0364.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51839948");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.1/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92f94c8a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:0364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1615673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1620529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628702");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15311");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15370");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15373");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15440");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15443");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15444");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15461");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15482");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15483");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15525");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15528");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15545");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15619");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15627");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15747");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15842");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15852");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-15891");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-16015");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-9658");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.1.6 on RHEL 6 package based on the guidance in
RHSA-2019:0364.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14642");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1000632");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 79, 88);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jdbc-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-el-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbosstxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbossxts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-web-console-eap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'eap7-activemq-artemis-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-cli-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-commons-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-core-client-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-dto-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-jdbc-store-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-jms-client-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-jms-server-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-journal-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-native-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-ra-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-selector-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-server-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-activemq-artemis-service-extensions-1.5.5.015-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-apache-cxf-3.1.16-2.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-apache-cxf-rt-3.1.16-2.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-apache-cxf-services-3.1.16-2.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-apache-cxf-tools-3.1.16-2.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-dom4j-2.1.1-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-core-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-entitymanager-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-envers-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-infinispan-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-hibernate-java8-5.1.17-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-common-api-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-common-impl-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-common-spi-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-core-api-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-core-impl-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-deployers-common-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-jdbc-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-ironjacamar-validator-1.4.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jackson-databind-2.8.11.3-1.redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jandex-2.0.5-1.Final_redhat_1.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jberet-1.2.7-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jberet-core-1.2.7-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-ejb-client-4.0.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-el-api_3.0_spec-1.0.13-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-logmanager-2.0.11-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-modules-1.6.7-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-security-negotiation-3.0.5-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jbossws-common-3.1.7-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-compensations-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-jbosstxbridge-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-jbossxts-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-jts-idlj-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-jts-integration-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-restat-api-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-restat-bridge-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-restat-integration-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-restat-util-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-narayana-txframework-5.5.34-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-api-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-bindings-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-common-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-config-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-federation-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-api-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-impl-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-15.SP12_redhat_3.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-undertow-1.4.18-10.SP11_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-undertow-jastow-2.0.7-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-7.1.6-4.GA_redhat_00002.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-common-1.2.1-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-elytron-1.1.12-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-elytron-tool-1.0.9-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-javadocs-7.1.6-2.GA_redhat_00002.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-modules-7.1.6-4.GA_redhat_00002.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-wildfly-web-console-eap-2.9.19-1.Final_redhat_00001.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-activemq-artemis / eap7-activemq-artemis-cli / etc');
}
