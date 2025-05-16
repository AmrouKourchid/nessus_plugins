#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7639. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186544);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-2976",
    "CVE-2023-4503",
    "CVE-2023-5685",
    "CVE-2023-26048",
    "CVE-2023-26049",
    "CVE-2023-35887",
    "CVE-2023-39410",
    "CVE-2023-44487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"RHSA", value:"2023:7639");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"RHEL 9 : Red Hat JBoss Enterprise Application Platform 7.4.14 on RHEL 9 (RHSA-2023:7639)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.4.14
on RHEL 9.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7639 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This release of Red Hat JBoss Enterprise Application Platform 7.4.14 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.4.13, and includes bug fixes and enhancements.

    See the Red Hat JBoss Enterprise Application Platform 7.4.14 Release Notes for information about the most
    significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * undertow: HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable to a DDoS attack (Rapid Reset
    Attack) (CVE-2023-44487)

    * avro: apache-avro: Apache Avro Java SDK: Memory when deserializing untrusted data in Avro Java SDK
    (CVE-2023-39410)

    * guava: insecure temporary directory creation (CVE-2023-2976)

    * eap-galleon: custom provisioning creates unsecured http-invoker (CVE-2023-4503)

    * jetty-server: OutOfMemoryError for large multipart without filename read via request.getParameter()
    (CVE-2023-26048)

    * jetty-server: Cookie parsing of quoted values can exfiltrate values from other cookies (CVE-2023-26049)

    * sshd-common: apache-mina-sshd: information exposure in SFTP server implementations (CVE-2023-35887)

    A Red Hat Security Bulletin which addresses further details about the Rapid Reset flaw is available in the
    References section.

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7639.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?507a0e38");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242803");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25004");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25085");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25086");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25378");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25380");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25419");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25451");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25457");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25541");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25547");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25576");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25594");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25627");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25657");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25685");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25700");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25716");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25726");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25772");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25779");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25803");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25838");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26041");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.4.14 on RHEL 9 package based on the guidance in
RHSA-2023:7639.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4503");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 400, 502, 552, 665, 770, 1286);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jsp-api_2.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling-river");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-yasson");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/debug',
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/os',
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-server-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-17.redhat_00051.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-apache-sshd-2.9.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-avro-1.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-39410']},
      {'reference':'eap7-guava-32.1.1-2.jre_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-2976', 'CVE-2023-26048']},
      {'reference':'eap7-guava-libraries-32.1.1-2.jre_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-2976', 'CVE-2023-26048']},
      {'reference':'eap7-hal-console-3.3.20-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-hibernate-5.3.32-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-hibernate-core-5.3.32-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-hibernate-envers-5.3.32-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-infinispan-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-cachestore-jdbc-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-cachestore-remote-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-client-hotrod-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-commons-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-component-annotations-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-core-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-hibernate-cache-commons-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-hibernate-cache-spi-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-infinispan-hibernate-cache-v53-11.0.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-jandex-2.4.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-jsp-api_2.3_spec-2.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-marshalling-2.0.14-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-marshalling-river-2.0.14-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-server-migration-1.10.0-33.Final_redhat_00032.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-33.Final_redhat_00032.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-33.Final_redhat_00032.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-jboss-xnio-base-3.8.11-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-5685', 'CVE-2023-26048']},
      {'reference':'eap7-jbossws-cxf-5.4.9-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-44487']},
      {'reference':'eap7-jgroups-4.2.23-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-undertow-2.2.28-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-weld-core-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-core-impl-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-core-jsf-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-ejb-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-jta-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-probe-core-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-weld-web-3.1.10-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']},
      {'reference':'eap7-wildfly-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-java-jdk11-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-java-jdk17-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-java-jdk8-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-javadocs-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-modules-7.4.14-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-4503', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-35887', 'CVE-2023-44487']},
      {'reference':'eap7-wildfly-transaction-client-1.1.16-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048', 'CVE-2023-26049']},
      {'reference':'eap7-yasson-1.0.11-4.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2023-26048']}
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
