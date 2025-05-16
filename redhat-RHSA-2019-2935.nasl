#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2935. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129516);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2019-10184",
    "CVE-2019-10202",
    "CVE-2019-10212",
    "CVE-2019-12086",
    "CVE-2019-12384",
    "CVE-2019-12814",
    "CVE-2019-14379"
  );
  script_xref(name:"RHSA", value:"2019:2935");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 7.2.4 on RHEL 6 Security update (Important) (RHSA-2019:2935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:2935 advisory.

    This release of Red Hat JBoss Enterprise Application Platform 7.2.4 serves as a replacement for Red Hat
    JBoss Enterprise Application Platform 7.2.3, and includes bug fixes and enhancements. See the Red Hat
    JBoss Enterprise Application Platform 7.2.4 Release Notes for information about the most significant bug
    fixes and enhancements included in this release.

    Security Fix(es):

    * jackson-databind: default typing mishandling leading to remote code execution (CVE-2019-14379)

    * jackson-databind: failure to block the logback-core class from polymorphic deserialization leading to
    remote code execution (CVE-2019-12384)

    * jackson-databind: polymorphic typing issue allows attacker to read arbitrary local files on the server
    via crafted JSON message (CVE-2019-12814)

    * undertow: DEBUG log for io.undertow.request.security if enabled leaks credentials to log files
    (CVE-2019-10212)

    * codehaus: incomplete fix for unsafe deserialization in jackson-databind vulnerabilities (CVE-2019-10202)

    * jackson-databind: polymorphic typing issue allows attacker to read arbitrary local files on the server
    (CVE-2019-12086)

    * undertow: Information leak in requests for directories without trailing slashes (CVE-2019-10184)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad39889");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_2935.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f4a0cbf");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/7.2/html-single/installation_guide/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdc49160");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2935");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1725795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1725807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1737517");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-16455");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-16779");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17045");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17062");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17073");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17109");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17112");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17142");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17162");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17178");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17182");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17183");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17223");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17238");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17250");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17271");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17273");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17274");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17276");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17277");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17278");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17294");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17311");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17320");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17321");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17334");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-17527");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 502, 532, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaxrs-api_2.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling-river");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-msc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly13.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly14.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
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
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-cli-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-commons-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-core-client-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-dto-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-jms-client-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-jms-server-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-journal-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-ra-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-selector-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-server-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-service-extensions-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-activemq-artemis-tools-2.9.0-1.redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-codehaus-jackson-1.9.13-9.redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10202', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-codehaus-jackson-core-asl-1.9.13-9.redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10202', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-codehaus-jackson-jaxrs-1.9.13-9.redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10202', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-codehaus-jackson-mapper-asl-1.9.13-9.redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10202', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-codehaus-jackson-xc-1.9.13-9.redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10202', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-glassfish-jsf-2.3.5-4.SP3_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hal-console-3.0.16-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hibernate-5.3.11-2.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hibernate-core-5.3.11-2.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hibernate-entitymanager-5.3.11-2.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hibernate-envers-5.3.11-2.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-hibernate-java8-5.3.11-2.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-cachestore-jdbc-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-cachestore-remote-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-client-hotrod-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-commons-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-core-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-hibernate-cache-commons-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-hibernate-cache-spi-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-infinispan-hibernate-cache-v53-9.3.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-common-api-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-common-impl-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-common-spi-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-core-api-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-core-impl-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-deployers-common-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-jdbc-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-ironjacamar-validator-1.4.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-annotations-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-core-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-databind-2.9.9.3-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-datatype-jdk8-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-datatype-jsr310-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-jaxrs-base-2.9.9-2.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-jaxrs-json-provider-2.9.9-2.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-module-jaxb-annotations-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-modules-base-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jackson-modules-java8-2.9.9-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-ejb-client-4.0.23-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-jaxrs-api_2.1_spec-1.0.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-logging-3.3.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-logmanager-2.1.14-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-marshalling-2.0.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-marshalling-river-2.0.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-msc-1.4.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-remoting-5.0.14-1.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-cli-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-core-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-4.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jboss-xnio-base-3.7.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-jgroups-4.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-compensations-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-jbosstxbridge-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-jbossxts-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-jts-idlj-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-jts-integration-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-restat-api-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-restat-bridge-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-restat-integration-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-restat-util-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-narayana-txframework-5.9.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-netty-4.1.34-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-netty-all-4.1.34-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketbox-5.0.3-5.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketbox-infinispan-5.0.3-5.Final_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-api-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-bindings-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-common-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-config-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-federation-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-idm-api-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-impl-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-20.SP12_redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-undertow-2.0.25-1.SP1_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-core-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-core-impl-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-core-jsf-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-ejb-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-jta-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-probe-core-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-weld-web-3.0.6-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-7.2.4-1.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-elytron-1.6.4-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-elytron-tool-1.4.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-javadocs-7.2.4-1.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-modules-7.2.4-1.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']},
      {'reference':'eap7-wildfly-transaction-client-1.1.6-2.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2019-10184', 'CVE-2019-10212', 'CVE-2019-12086', 'CVE-2019-12384', 'CVE-2019-12814', 'CVE-2019-14379']}
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
