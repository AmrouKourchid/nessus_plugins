#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2539. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87193);
  script_version("2.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/24");

  script_cve_id("CVE-2015-5304", "CVE-2015-7501");
  script_xref(name:"RHSA", value:"2015:2539");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 6.4.5 update (Critical) (RHSA-2015:2539)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:2539 advisory.

  - JBoss EAP: missing authorization check for Monitor/Deployer/Auditor role when shutting down server
    (CVE-2015-5304)

  - apache-commons-collections: InvokerTransformer code execution during deserialisation (CVE-2015-7501)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2015/rhsa-2015_2539.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6da92d6");
  # https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/6.4/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec52744e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:2539");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1279330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1279592");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7501");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(284, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-spi-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-deployers-common-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-jdbc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-spec-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-validator-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-client-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-clustering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-core-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ejb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-host-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jpa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsr77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-management-client-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-modcluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-picketlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-platform-mbean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-process-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-sar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-system-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-webservices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-weld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-xts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsf-api_2.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-commons-collections-eap6-3.2.1-18.redhat_7.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-core-eap6-4.2.21-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-eap6-4.2.21-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-entitymanager-eap6-4.2.21-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-envers-eap6-4.2.21-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-infinispan-eap6-4.2.21-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-2.3.25-7.SP6_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-api-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-impl-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-spi-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-api-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-impl-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-deployers-common-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-jdbc-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-spec-api-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-validator-eap6-1.0.34-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-appclient-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cli-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-client-all-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-clustering-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cmp-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-configadmin-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-connector-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-console-2.5.11-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-client-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-core-security-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-repository-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-scanner-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-http-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-management-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-deployment-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ejb3-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-embedded-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-host-controller-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jacorb-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxr-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxrs-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jdr-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jmx-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jpa-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsf-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsr77-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-logging-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-mail-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-management-client-content-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-messaging-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-modcluster-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-naming-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-network-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-configadmin-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-service-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-picketlink-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-platform-mbean-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-pojo-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-process-controller-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-protocol-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-remoting-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-sar-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-security-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-server-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-system-jmx-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-threads-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-transactions-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-version-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-web-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-webservices-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-weld-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-xts-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-ejb-client-1.0.32-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-hal-2.5.11-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jsf-api_2.1_spec-2.1.28-5.SP1_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-remoting3-3.3.6-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-security-negotiation-2.3.10-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-xnio-base-3.0.15-1.GA_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-appclient-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-bundles-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-core-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-domain-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-javadocs-7.5.5-3.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-modules-eap-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-product-eap-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-standalone-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-welcome-content-eap-7.5.5-2.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossweb-7.5.12-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketbox-4.1.2-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections-eap6 / hibernate4-core-eap6 / etc');
}
