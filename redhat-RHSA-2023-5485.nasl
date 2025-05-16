#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5485. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182683);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-25883",
    "CVE-2023-3171",
    "CVE-2023-4061",
    "CVE-2023-26136",
    "CVE-2023-26464",
    "CVE-2023-33201",
    "CVE-2023-34462"
  );
  script_xref(name:"RHSA", value:"2023:5485");
  script_xref(name:"IAVA", value:"2023-A-0532-S");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.13 security update on RHEL 8 (Important) (RHSA-2023:5485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform
7.4.13.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5485 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This release of Red Hat JBoss Enterprise Application Platform 7.4.13 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.4.12 and includes bug fixes and enhancements. See the Red Hat
    JBoss Enterprise Application Platform 7.4.13 Release Notes for information about the most significant bug
    fixes and enhancements included in this release.

    Security Fix(es):

    * server: eap-7: heap exhaustion via deserialization (CVE-2023-3171)

    * log4j: log4j1-chainsaw, log4j1-socketappender: DoS via hashmap logging (CVE-2023-26464)

    * nodejs-semver: Regular expression denial of service (CVE-2022-25883)

    * wildfly-core: Management User RBAC permission allows unexpected reading of system-properties to an
    Unauthorized actor (CVE-2023-4061)

    * tough-cookie: prototype pollution in cookie memstore (CVE-2023-26136)

    * bouncycastle: potential blind LDAP injection attack using a self-signed certificate (CVE-2023-33201)

    * netty: netty-handler: SniHandler 16MB allocation (CVE-2023-34462)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5485.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d88394c");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2182864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2219310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228608");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24667");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24798");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24966");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24985");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25032");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25033");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25078");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25122");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25135");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25186");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25200");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25225");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25261");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25285");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25312");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5485");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.4.13 package based on the guidance in RHSA-2023:5485.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 400, 770, 789, 1321, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling-river");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-mqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-socks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns-classes-macos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-kqueue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-unix-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-rxtx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-sctp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-udt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      {'reference':'eap7-activemq-artemis-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-server-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-15.redhat_00049.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-bouncycastle-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-bouncycastle-mail-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-bouncycastle-pg-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-bouncycastle-pkix-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-bouncycastle-prov-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-bouncycastle-util-1.76.0-4.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-33201']},
      {'reference':'eap7-hal-console-3.3.19-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-hibernate-5.3.31-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-hibernate-core-5.3.31-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-hibernate-entitymanager-5.3.31-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-hibernate-envers-5.3.31-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-hibernate-java8-5.3.31-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-common-api-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-common-impl-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-common-spi-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-core-api-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-core-impl-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-deployers-common-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-jdbc-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-ironjacamar-validator-1.5.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-marshalling-2.0.13-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-marshalling-river-2.0.13-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-modules-1.12.2-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-server-migration-1.10.0-31.Final_redhat_00030.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-31.Final_redhat_00030.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-31.Final_redhat_00030.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-jboss-xnio-base-3.8.10-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-mod_cluster-1.4.5-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-netty-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-all-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-buffer-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-dns-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-haproxy-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-http-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-http2-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-memcache-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-mqtt-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-redis-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-smtp-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-socks-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-stomp-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-codec-xml-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-common-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-handler-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-handler-proxy-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-resolver-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-resolver-dns-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-resolver-dns-classes-macos-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-classes-epoll-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-classes-kqueue-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-native-epoll-4.1.94-1.Final_redhat_00001.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-native-unix-common-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-rxtx-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-sctp-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-netty-transport-udt-4.1.94-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464', 'CVE-2023-34462']},
      {'reference':'eap7-resteasy-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-atom-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-cdi-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-client-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-crypto-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jackson-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jackson2-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jaxb-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jaxrs-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jettison-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jose-jwt-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-jsapi-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-json-binding-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-json-p-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-multipart-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-rxjava2-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-spring-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-validator-provider-11-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-resteasy-yaml-provider-3.15.8-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-undertow-2.2.26-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-elytron-1.15.20-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-elytron-tool-1.15.20-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-java-jdk11-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-java-jdk17-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-java-jdk8-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-javadocs-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']},
      {'reference':'eap7-wildfly-modules-7.4.13-8.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-25883', 'CVE-2023-3171', 'CVE-2023-4061', 'CVE-2023-26136', 'CVE-2023-26464']}
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
