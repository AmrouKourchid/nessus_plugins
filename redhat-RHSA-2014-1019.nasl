#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1019. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77078);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id(
    "CVE-2014-0118",
    "CVE-2014-0193",
    "CVE-2014-0226",
    "CVE-2014-0227",
    "CVE-2014-0231",
    "CVE-2014-3464",
    "CVE-2014-3472"
  );
  script_bugtraq_id(69094, 69332);
  script_xref(name:"RHSA", value:"2014:1019");

  script_name(english:"RHEL 5 : Red Hat JBoss Enterprise Application Platform 6.3.0 update (Important) (RHSA-2014:1019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1019 advisory.

    Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
    applications based on JBoss Application Server 7.

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

    A flaw was found in the WebSocket08FrameDecoder implementation that could
    allow a remote attacker to trigger an Out Of Memory Exception by issuing a
    series of TextWebSocketFrame and ContinuationWebSocketFrames. Depending on
    the server configuration, this could lead to a denial of service.
    (CVE-2014-0193)

    It was found that the isCallerInRole() method of the SimpleSecurityManager
    did not correctly check caller roles. A remote, authenticated attacker
    could use this flaw to circumvent the caller check in applications that use
    black list access control based on caller roles. (CVE-2014-3472)

    Red Hat would like to thank James Roper of Typesafe for reporting
    CVE-2014-0193, and CA Technologies for reporting CVE-2014-3472.

    This release of JBoss Enterprise Application Platform also includes bug
    fixes and enhancements. Documentation for these changes will be available
    shortly from the JBoss Enterprise Application Platform 6.3.0 Release Notes,
    linked to in the References.

    All users who require JBoss Enterprise Application Platform 6.3.0 on Red
    Hat Enterprise Linux 5 should install these new packages. The JBoss server
    process must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/6.3/html/6.3.0_Release_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8937e67e");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1019.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c720f7b0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1019");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1038658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1052745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1067505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1067567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1069415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1071414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1072567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1072592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1078673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1080388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1080714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1080722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1080776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1081266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1081631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1082057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1084348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1086793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1092089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1092104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1092783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1102510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1102513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1103815");
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
  script_cwe_id(122, 184, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-beanutils-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-configuration-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-jsvc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cal10n-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-getopt-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpclient-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-project-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcore-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpmime-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-core");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jandex-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen-eap6");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxws-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jstl-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-msc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-saaj-api_1.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-jbossweb-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:joda-time-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rngom-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snakeyaml-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stilts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-stax2-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmltooling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xom");
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
      'content/dist/rhel/server/5/5Server/i386/jbeap/6.3/os',
      'content/dist/rhel/server/5/5Server/i386/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/jbeap/6.4/os',
      'content/dist/rhel/server/5/5Server/i386/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/jbeap/6/os',
      'content/dist/rhel/server/5/5Server/i386/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-commons-beanutils-eap6-1.8.3-7.redhat_6.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-cli-eap6-1.2-6.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-codec-eap6-1.4-16.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-collections-eap6-3.2.1-15.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-configuration-eap6-1.6-1.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-daemon-jsvc-eap6-1.0.15-6.redhat_2.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'apache-commons-daemon-jsvc-eap6-1.0.15-6.redhat_2.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'apache-commons-io-eap6-2.1-8.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-lang-eap6-2.6-8.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-mime4j-0.6-10.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'cal10n-eap6-0.7.3-2.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-1.9.9-7.redhat_3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-core-asl-1.9.9-7.redhat_3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-jaxrs-1.9.9-7.redhat_3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-mapper-asl-1.9.9-7.redhat_3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-xc-1.9.9-7.redhat_3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ecj-eap6-4.3.1-3.redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'glassfish-jaxb-eap6-2.2.5-20.redhat_8.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'gnu-getopt-eap6-1.0.13-1.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'guava-libraries-13.0.1-3.redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'h2database-1.3.168-7.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-core-eap6-4.2.14-2.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-eap6-4.2.14-2.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-entitymanager-eap6-4.2.14-2.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-envers-eap6-4.2.14-2.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-infinispan-eap6-4.2.14-2.SP1_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-validator-4.3.1-2.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-2.3.20-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-native-2.3.20-2.Final_redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-native-2.3.20-2.Final_redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpclient-eap6-4.2.1-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-client-eap6-4.2.1-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-core-eap6-4.2.1-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-project-eap6-6-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcore-eap6-4.2.1-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-devel-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-devel-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-manual-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-manual-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-tools-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-tools-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpmime-eap6-4.2.1-10.redhat_1.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-5.2.10-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-cachestore-jdbc-5.2.10-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-cachestore-remote-5.2.10-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-client-hotrod-5.2.10-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-core-5.2.10-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-api-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-impl-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-spi-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-api-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-impl-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-deployers-common-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-jdbc-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-spec-api-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-validator-eap6-1.0.26-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jandex-eap6-1.0.3-3.Final_redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jansi-eap6-1.9-2.redhat_4.3.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jaxbintros-1.0.2-17.GA_redhat_6.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jaxen-eap6-1.1.3-2.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-appclient-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cli-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-client-all-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-clustering-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cmp-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-configadmin-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-connector-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-console-2.2.8-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-client-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-core-security-7.4.0-15.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-repository-7.4.0-14.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-scanner-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-http-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-management-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-deployment-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ejb3-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-embedded-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-host-controller-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jacorb-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxr-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxrs-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jdr-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jmx-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jpa-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsf-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsr77-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-logging-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-mail-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-management-client-content-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-messaging-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-modcluster-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-naming-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-network-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-configadmin-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-service-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-picketlink-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-platform-mbean-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-pojo-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-process-controller-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-protocol-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-remoting-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-sar-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-security-7.4.0-14.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-server-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-system-jmx-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-threads-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-transactions-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-version-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-web-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-webservices-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-weld-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-xts-7.4.0-13.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-genericjms-1.0.5-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-hal-2.2.8-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaxws-api_2.2_spec-2.0.2-4.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jms-api_1.1_spec-1.0.1-8.Final_redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jstl-api_1.2_spec-1.0.6-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-logging-3.1.4-1.GA_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-marshalling-1.4.6-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-appclient-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-common-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-ear-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-ejb-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-web-7.1.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-msc-1.1.5-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-remoting3-3.3.1-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-saaj-api_1.3_spec-1.0.3-3.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-sasl-1.0.4-2.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-security-negotiation-2.3.3-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-transaction-api_1.1_spec-1.0.1-10.Final_redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-transaction-spi-7.1.0-2.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-vfs2-3.2.5-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-appclient-7.4.0-15.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-bundles-7.4.0-15.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-core-7.4.0-16.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-domain-7.4.0-15.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-hornetq-native-2.3.20-2.Final_redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-hornetq-native-2.3.20-2.Final_redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-javadocs-7.4.0-20.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-jbossweb-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-jbossweb-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-modules-eap-7.4.0-38.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-product-eap-7.4.0-19.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-standalone-7.4.0-15.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-welcome-content-eap-7.4.0-17.Final_redhat_19.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossts-4.17.21-2.Final_redhat_2.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbossweb-7.4.8-4.Final_redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossws-common-2.3.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossws-cxf-4.3.0-3.Final_redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossws-native-4.2.0-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossws-spi-2.3.0-2.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jdom-eap6-1.1.2-6.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jettison-eap6-1.3.1-3.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jgroups-3.2.13-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'joda-time-eap6-1.6.2-1.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jython-eap6-2.5.2-6.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-1.2.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-demo-1.2.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.9-3.Final_redhat_2.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.9-3.Final_redhat_2.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_jk-ap22-1.2.40-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_jk-ap22-1.2.40-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_rt-2.4.1-3.GA.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_rt-2.4.1-3.GA.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_snmp-2.4.1-7.GA.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_snmp-2.4.1-7.GA.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ssl-2.2.26-35.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_ssl-2.2.26-35.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'netty-3.6.9-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'opensaml-2.5.3-4.redhat_2.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'openws-1.4.4-3.redhat_2.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketlink-bindings-2.5.3-8.SP10_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketlink-federation-2.5.3-9.SP10_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'resteasy-2.3.8-4.Final_redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'rngom-eap6-201103-2.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'scannotation-1.0.3-6.redhat_4.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'slf4j-1.7.2-13.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'slf4j-eap6-1.7.2-13.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'slf4j-jboss-logmanager-1.0.3-1.GA_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'snakeyaml-eap6-1.8-1.redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'stilts-0.1.26-13.redhat_4.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-codemodel-2.6-4.redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-istack-commons-2.6.1-10.redhat_2.2.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'sun-saaj-1.3-impl-1.3.16-9.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-txw2-20110809-7.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-xsom-20110809-7.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'tomcat-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'tomcat-native-1.1.30-2.redhat_1.ep6.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'weld-core-1.1.23-1.Final_redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'woodstox-core-eap6-4.2.0-12.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'woodstox-stax2-api-eap6-3.1.3-3.redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ws-commons-neethi-3.0.2-8.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'wsdl4j-eap6-1.6.3-1.redhat_1.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'xml-commons-resolver-eap6-1.2-17.redhat_9.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'xmltooling-1.3.4-6.redhat_3.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'xom-1.2.7-3.redhat_4.1.ep6.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-beanutils-eap6 / apache-commons-cli-eap6 / etc');
}
