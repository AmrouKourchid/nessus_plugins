#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1675. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192929);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id(
    "CVE-2023-1973",
    "CVE-2023-4639",
    "CVE-2023-48795",
    "CVE-2024-1459",
    "CVE-2024-1635"
  );
  script_xref(name:"RHSA", value:"2024:1675");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.16 Security update (Important) (RHSA-2024:1675)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:1675 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 7.4.16 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 7.4.15, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 7.4.16 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * undertow: Cookie Smuggling/Spoofing [eap-7.4.z] (CVE-2023-4639)

    * apache-sshd: ssh: Prefix truncation attack on Binary Packet Protocol (BPP) [eap-7.4.z] (CVE-2023-48795)

    * undertow: unrestricted request storage leads to memory exhaustion [eap-7.4.z] (CVE-2023-1973)

    * undertow: Out-of-memory Error after several closed connections with wildfly-http-client protocol
    [eap-7.4.z] (CVE-2024-1635)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1675.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60693768");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2185662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264928");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-19969");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26168");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26280");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26291");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26318");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26343");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26355");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26414");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26467");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26533");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26552");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26587");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26616");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26617");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26636");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1675");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4639");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 222, 24, 400, 444);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-elytron-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-insights-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-annotations-api_1.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-cert-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-analyzers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-backward-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-facet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-grouping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/debug',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/os',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-server-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-18.redhat_00052.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-apache-cxf-3.4.10-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-apache-cxf-rt-3.4.10-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-apache-cxf-services-3.4.10-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-apache-cxf-tools-3.4.10-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-eclipse-jgit-5.13.3.202401111512-1.r_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hal-console-3.3.21-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hibernate-5.3.36-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hibernate-core-5.3.36-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hibernate-entitymanager-5.3.36-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hibernate-envers-5.3.36-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-hibernate-java8-5.3.36-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-cachestore-jdbc-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-cachestore-remote-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-client-hotrod-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-commons-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-component-annotations-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-core-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-hibernate-cache-commons-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-hibernate-cache-spi-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-infinispan-hibernate-cache-v53-11.0.18-2.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-insights-java-client-1.1.2-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jberet-1.3.9-3.SP3_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jberet-core-1.3.9-3.SP3_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-annotations-api_1.3_spec-2.0.1-3.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-cert-helper-1.1.2-1.redhat_00001.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-remoting-5.0.27-4.SP2_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-server-migration-1.10.0-35.Final_redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-35.Final_redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-35.Final_redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jboss-xnio-base-3.8.12-1.SP2_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-jgroups-kubernetes-1.0.17-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-analyzers-common-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-backward-codecs-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-core-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-facet-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-grouping-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-misc-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-queries-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-queryparser-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-lucene-solr-5.5.5-6.redhat_2.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-undertow-2.2.30-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-1973', 'CVE-2023-4639', 'CVE-2023-48795', 'CVE-2024-1459', 'CVE-2024-1635']},
      {'reference':'eap7-undertow-server-1.9.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-elytron-1.15.22-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-elytron-tool-1.15.22-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-java-jdk11-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-java-jdk17-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-java-jdk8-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-javadocs-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']},
      {'reference':'eap7-wildfly-modules-7.4.16-4.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-48795', 'CVE-2024-1459']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-activemq-artemis / eap7-activemq-artemis-cli / etc');
}
