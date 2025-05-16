#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1802. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2011-4314");
  script_xref(name:"RHSA", value:"2011:1802");

  script_name(english:"RHEL 6 : JBoss Enterprise Web Platform 5.1.2 update (Low) (RHSA-2011:1802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2011:1802 advisory.

    The Enterprise Web Platform is a slimmed down profile of the JBoss
    Enterprise Application Platform intended for mid-size workloads with light
    and rich Java applications. OpenID4Java allows you to implement OpenID
    authentication in your Java applications. OpenID4Java is a Technology
    Preview.

    This JBoss Enterprise Web Platform 5.1.2 release for Red Hat Enterprise
    Linux 6 serves as a replacement for JBoss Enterprise Web Platform 5.1.1.

    These updated packages include bug fixes and enhancements. JBoss Enterprise
    Web Platform is a subset of JBoss Enterprise Application Platform. Users
    are directed to the JBoss Enterprise Application Platform 5.1.2 Release
    Notes for information on the most significant of these changes. The Release
    Notes will be available shortly from
    https://docs.redhat.com/docs/en-US/index.html

    The following security issue is also fixed with this release:

    It was found that the Attribute Exchange (AX) extension of OpenID4Java was
    not checking to ensure attributes were signed. If AX was being used to
    receive information that an application only trusts the identity provider
    to assert, a remote attacker could use this flaw to conduct
    man-in-the-middle attacks and compromise the integrity of the information
    via a specially-crafted request. By default, only the JBoss Seam openid
    example application uses OpenID4Java. (CVE-2011-4314)

    Warning: Before applying this update, back up the
    jboss-as-web/server/[PROFILE]/deploy/ directory and any other customized
    configuration files of your JBoss Enterprise Web Platform.

    All users of JBoss Enterprise Web Platform 5.1.1 on Red Hat Enterprise
    Linux 6 are advised to upgrade to these updated packages. The JBoss server
    process must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_1802.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4baffb9d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://docs.redhat.com/docs/en-US/index.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/support/offerings/techpreview/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=733745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=754386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1802");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4314");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facelets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-clustered");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-web-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-web-tp-licenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-web-ws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf-ewp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosssx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org-mc4j-ems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-idp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-sts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ewp-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ewp-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-ant-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-common-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-comm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-dbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-native-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugindoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-filetemplate-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jboss-as-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jmx-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-modules-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-platform-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugin-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginAnnotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginGen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugins-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-rtfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-cxf-2.2.12-4.patch_02.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cglib-2.2-5.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'facelets-1.1.15-3.B1_patch_01.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-2.1.12-10_patch_02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jsf-1.2_13-5_patch_01.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jacorb-jboss-2.3.1-10.patch_03.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jakarta-commons-logging-jboss-1.1-10.3_patch_02.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-aop2-2.1.6-2.CP03.1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-cache-core-3.2.8-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-cl-2.0.10-1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-cluster-ha-client-1.1.4-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-common-core-2.2.18-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-eap5-native-5.1.2-1.4.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-eap5-native-5.1.2-1.4.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-ejb3-core-1.3.8-0.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-ejb3-proxy-clustered-1.0.3-2.SP1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-ejb3-proxy-impl-1.0.6-2.SP2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-el-1.0_02-0.CR6.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-naming-5.0.3-3.CP01.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-remoting-2.5.4-9.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-2.2.5.EAP5-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-docs-2.2.5.EAP5-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-examples-2.2.5.EAP5-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-runtime-2.2.5.EAP5-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-security-spi-2.0.4-6.SP8.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jbossas-web-5.1.2-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossas-web-client-5.1.2-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossas-web-tp-licenses-5.1.2-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossas-web-ws-native-5.1.2-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossas-ws-cxf-ewp-5.1.2-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbosssx2-2.0.4-6.SP8.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossts-4.6.1-11.CP12.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jbossts-javadoc-4.6.1-11.CP12.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jbossweb-2.1.12-1.4_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossweb-el-1.0-api-2.1.12-1.4_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossweb-jsp-2.1-api-2.1.12-1.4_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossweb-lib-2.1.12-1.4_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossweb-servlet-2.5-api-2.1.12-1.4_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-3.1.2-7.SP11.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-common-1.1.0-6.SP8_patch_01.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-framework-3.1.2-6.SP10.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-spi-1.1.2-5.SP7.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jgroups-2.6.20-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jopr-embedded-1.3.4-18.SP5.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jopr-hibernate-plugin-3.0.0-13.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jopr-jboss-as-5-plugin-3.0.0-12.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jopr-jboss-cache-v3-plugin-3.0.0-14.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-demo-1.0.10-3.2.GA_CP02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-jbossas-1.0.10-3.2.GA_CP02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-jbossweb2-1.0.10-3.2.GA_CP02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-native-1.0.10-3.1.1.GA_CP02.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-native-1.0.10-3.1.1.GA_CP02.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_cluster-tomcat6-1.0.10-3.2.GA_CP02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'org-mc4j-ems-1.2.15.1-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'picketlink-federation-2.0.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'picketlink-federation-webapp-idp-2.0.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'picketlink-federation-webapp-pdp-2.0.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'picketlink-federation-webapp-sts-2.0.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-1.2.1-9.CP02.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-examples-1.2.1-9.CP02.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-javadoc-1.2.1-9.CP02.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-manual-1.2.1-9.CP02.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ewp-docs-5.1.2-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ewp-docs-examples-5.1.2-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-ant-bundle-common-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-common-parent-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-client-api-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-comm-api-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-dbutils-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-domain-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-gui-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-native-system-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-parent-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-plugin-api-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-plugin-container-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-plugindoc-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-core-util-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-filetemplate-bundle-common-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-helpers-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-jboss-as-common-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-jmx-plugin-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-modules-parent-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-parent-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-platform-plugin-3.0.0-13.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-plugin-validator-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-pluginAnnotations-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-pluginGen-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-plugins-parent-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rhq-rtfilter-3.0.0-20.EmbJopr4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.5.8-10_patch_01.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-6_patch_05.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-cxf / cglib / facelets / glassfish-jaxb / glassfish-jsf / etc');
}
