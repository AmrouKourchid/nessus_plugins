#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1514. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(173691);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2022-1471",
    "CVE-2022-4492",
    "CVE-2022-38752",
    "CVE-2022-41853",
    "CVE-2022-41854",
    "CVE-2022-41881",
    "CVE-2022-45787",
    "CVE-2023-0482",
    "CVE-2023-1108"
  );
  script_xref(name:"RHSA", value:"2023:1514");

  script_name(english:"RHEL 9 : Red Hat JBoss Enterprise Application Platform 7.4.10 on RHEL 9 (RHSA-2023:1514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.4.10
on RHEL 9.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:1514 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime.

    This release of Red Hat JBoss Enterprise Application Platform 7.4.10 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.4.9, and includes bug fixes and enhancements. See the Red Hat
    JBoss Enterprise Application Platform 7.4.10 Release Notes for information about the most significant bug
    fixes and enhancements included in this release.

    Security Fix(es):

    * SnakeYaml: Constructor Deserialization Remote Code Execution (CVE-2022-1471)

    * hsqldb: Untrusted input may lead to RCE attack (CVE-2022-41853)

    * Undertow: Infinite loop in SslConduit during close (CVE-2023-1108)

    * undertow: Server identity in https connection is not checked by the undertow client (CVE-2022-4492)

    * snakeyaml: Uncaught exception in java.base/java.util.ArrayList.hashCode (CVE-2022-38752)

    * dev-java/snakeyaml: DoS via stack overflow (CVE-2022-41854)

    * codec-haproxy: HAProxyMessageDecoder Stack Exhaustion DoS (CVE-2022-41881)

    * apache-james-mime4j: Temporary File Information Disclosure in MIME4J TempFileStorageProvider
    (CVE-2022-45787)

    * RESTEasy: creation of insecure temp files (CVE-2023-0482)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327e7d12");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.4/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a15247");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_1514.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2a860fc");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2129710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2150009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2151988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2158916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174246");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-23572");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24122");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24172");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24182");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24220");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24254");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24292");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24339");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24341");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24363");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24372");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24380");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24383");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24384");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24385");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24395");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24507");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24535");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24574");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24588");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24605");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-24618");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.4.10 on RHEL 9 package based on the guidance in
RHSA-2023:1514.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 378, 470, 502, 550, 674, 787, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-wildfly-integration");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-el-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
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
      {'reference':'eap7-activemq-artemis-native-1.0.2-3.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-apache-mime4j-0.8.9-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-artemis-native-1.0.2-4.redhat_00004.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-artemis-native-wildfly-1.0.2-4.redhat_00004.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-artemis-wildfly-integration-1.0.7-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-cachestore-jdbc-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-cachestore-remote-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-client-hotrod-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-commons-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-component-annotations-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-core-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-hibernate-cache-commons-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-hibernate-cache-spi-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-infinispan-hibernate-cache-v53-11.0.17-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-common-api-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-common-impl-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-common-spi-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-core-api-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-core-impl-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-deployers-common-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-jdbc-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-ironjacamar-validator-1.5.11-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-ejb-client-4.0.50-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-el-api_3.0_spec-2.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-appclient-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-common-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-ear-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-ejb-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-metadata-web-13.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-server-migration-1.10.0-26.Final_redhat_00025.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-26.Final_redhat_00025.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-26.Final_redhat_00025.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jbossws-cxf-5.4.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-jbossws-spi-3.4.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-netty-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-buffer-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-dns-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-haproxy-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-http-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-http2-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-memcache-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-mqtt-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-redis-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-smtp-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-socks-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-stomp-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-codec-xml-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-common-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-handler-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-handler-proxy-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-resolver-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-resolver-dns-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-resolver-dns-classes-macos-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-classes-epoll-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-classes-kqueue-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-native-epoll-4.1.86-1.Final_redhat_00001.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-native-unix-common-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-rxtx-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-sctp-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-netty-transport-udt-4.1.86-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-41881', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-api-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-common-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-config-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-federation-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-idm-api-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-picketlink-impl-2.5.5-22.SP12_redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-resteasy-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-atom-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-cdi-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-client-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-crypto-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jackson-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jackson2-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jaxb-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jaxrs-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jettison-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jose-jwt-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-jsapi-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-json-binding-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-json-p-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-multipart-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-rxjava2-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-spring-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-validator-provider-11-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-resteasy-yaml-provider-3.15.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-0482']},
      {'reference':'eap7-snakeyaml-1.33.0-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-1471', 'CVE-2022-38752', 'CVE-2022-41853', 'CVE-2022-41854', 'CVE-2022-45787']},
      {'reference':'eap7-undertow-2.2.23-1.SP2_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-4492', 'CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-1108']},
      {'reference':'eap7-undertow-jastow-2.0.14-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-4492', 'CVE-2022-41853', 'CVE-2022-45787', 'CVE-2023-1108']},
      {'reference':'eap7-wildfly-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-http-client-common-1.1.16-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-http-ejb-client-1.1.16-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-http-naming-client-1.1.16-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-http-transaction-client-1.1.16-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-java-jdk11-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-java-jdk17-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-java-jdk8-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-javadocs-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']},
      {'reference':'eap7-wildfly-modules-7.4.10-6.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2022-41853', 'CVE-2022-45787']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-activemq-artemis-native / eap7-apache-mime4j / etc');
}
