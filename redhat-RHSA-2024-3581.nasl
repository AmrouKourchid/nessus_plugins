#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3581. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200098);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-4503",
    "CVE-2023-6236",
    "CVE-2024-1102",
    "CVE-2024-1233"
  );
  script_xref(name:"RHSA", value:"2024:3581");
  script_xref(name:"IAVA", value:"2024-A-0331");

  script_name(english:"RHEL 9 : Red Hat JBoss Enterprise Application Platform 8.0.2 Security update (Moderate) (RHSA-2024:3581)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:3581 advisory.

    Red Hat JBoss Enterprise Application Platform 8 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 8.0.2 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 8.0.1, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 8.0.2 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * jberet-core: jberet: jberet-core logging database credentials [eap-8.0.z] (CVE-2024-1102)

    * eap-galleon: custom provisioning creates unsecured http-invoker [eap-8.0.z] (CVE-2023-4503)

    * eap: JBoss EAP: wildfly-elytron has a SSRF security issue [eap-8.0.z] (CVE-2024-1233)

    * eap: JBoss EAP: OIDC app attempting to access the second tenant, the user should be prompted to log
    [eap-8.0.z] (CVE-2023-6236)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/8.0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?919aa761");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_3581.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6e5f7c1");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262849");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25251");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25263");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25292");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25379");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25638");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25787");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26024");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26205");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26224");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26290");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26407");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26468");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26529");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26532");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26573");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26588");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26635");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26637");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26642");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26651");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26677");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26681");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26758");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26766");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26770");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26806");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26812");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26813");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26832");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26864");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26868");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26881");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26933");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26937");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26954");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27002");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27009");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3581");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(345, 523, 665, 918);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-jakarta-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-jakarta-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-jakarta-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-jakarta-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-jdbc-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-amazon-ion-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus-activation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-antlr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-antlr4-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-caffeine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-elytron-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-fge-btf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-fge-msg-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-gson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava-failureaccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-backend-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-backend-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-mapper-orm-orm6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-mapper-pojo-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-search-util-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-httpcomponents-asyncclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cachestore-jdbc-common-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cachestore-jdbc-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cdi-common-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cdi-embedded-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-cdi-remote-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-client-hotrod-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-clustered-counter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-clustered-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-commons-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-core-jakarta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-hibernate-cache-v62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-objectfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-query");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-query-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-query-dsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-infinispan-remote-query-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-insights-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-istack-commons-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-istack-commons-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-dataformat-cbor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-dataformats-binary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-module-jakarta-xmlbind-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-activation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-annotation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-batch-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-interceptor-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-jms-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-json-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-servlet-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-transaction-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-validation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-ws-rs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-xml-bind-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jasypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-java-classmate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-javaee-jpa-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-xjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-cert-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jgroups-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jose4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-log4j2-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-analyzers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-facet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-join");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-lucene-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-jbosstxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-jbossxts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-codec-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-codec-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-codec-socks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-handler-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-resolver-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-transport-classes-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-transport-native-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-transport-native-unix-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-protostream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-reactive-streams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-relaxng-datatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-core-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-resteasy-validator-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-slf4j-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-velocity-engine-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-http-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wsdl4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-yasson");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/debug',
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/os',
      'content/dist/layered/rhel9/x86_64/jbeap/8.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap8-activemq-artemis-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-cli-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-commons-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-core-client-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-dto-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-hornetq-protocol-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-hqclient-protocol-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-jakarta-client-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-jakarta-ra-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-jakarta-server-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-jakarta-service-extensions-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-jdbc-store-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-journal-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-selector-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-activemq-artemis-server-2.21.0-4.redhat_00048.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-amazon-ion-java-1.0.2-4.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-angus-activation-2.0.1-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-angus-mail-2.0.2-3.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-antlr4-4.10.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-antlr4-runtime-4.10.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-commons-beanutils-1.9.4-12.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-commons-codec-1.15.0-5.redhat_00015.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-commons-io-2.11.0-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-cxf-4.0.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-cxf-rt-4.0.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-cxf-services-4.0.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-cxf-tools-4.0.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-apache-sshd-2.12.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-atinject-2.0.1-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-caffeine-3.1.8-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-codemodel-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-elytron-web-4.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2023-6236', 'CVE-2024-1233']},
      {'reference':'eap8-fge-btf-1.2.0-2.redhat_00017.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-fge-msg-simple-1.1.0-2.redhat_00015.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-gson-2.8.9-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-guava-32.1.2-1.jre_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-guava-failureaccess-1.0.1-4.redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-guava-libraries-32.1.2-1.jre_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hal-console-3.6.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hibernate-6.2.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hibernate-core-6.2.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hibernate-envers-6.2.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hibernate-search-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-backend-elasticsearch-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-backend-lucene-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-engine-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-mapper-orm-orm6-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-mapper-pojo-base-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-search-util-common-6.2.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-hibernate-validator-8.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-hibernate-validator-cdi-8.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-httpcomponents-asyncclient-4.1.5-2.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-httpcomponents-client-4.5.14-2.redhat_00010.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-httpcomponents-core-4.4.16-2.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cachestore-jdbc-common-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cachestore-jdbc-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cachestore-remote-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cdi-common-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cdi-embedded-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-cdi-remote-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-client-hotrod-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-clustered-counter-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-clustered-lock-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-commons-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-component-annotations-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-core-jakarta-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-hibernate-cache-commons-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-hibernate-cache-spi-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-hibernate-cache-v62-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-objectfilter-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-query-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-query-core-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-query-dsl-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-infinispan-remote-query-client-14.0.24-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-insights-java-client-1.1.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-common-api-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-common-impl-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-common-spi-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-core-api-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-core-impl-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-deployers-common-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-jdbc-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ironjacamar-validator-3.0.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-istack-commons-runtime-4.1.2-1.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-istack-commons-tools-4.1.2-1.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-annotations-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-core-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-databind-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-dataformat-cbor-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-dataformats-binary-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-datatype-jdk8-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-datatype-jsr310-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-jaxrs-base-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-jaxrs-json-provider-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-module-jakarta-xmlbind-annotations-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-modules-base-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jackson-modules-java8-2.15.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-activation-2.1.2-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-annotation-api-2.1.1-4.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-batch-api-2.1.1-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-interceptor-api-2.1.0-4.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-jms-api-3.1.0-4.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-json-1.1.6-4.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-json-api-2.1.2-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-mail-2.1.2-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-servlet-api-6.0.0-4.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-transaction-api-2.0.1-3.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-validation-api-3.0.2-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-ws-rs-api-3.1.0-4.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jakarta-xml-bind-api-4.0.0-4.redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jasypt-1.9.3-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-java-classmate-1.5.1-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-javaee-jpa-spec-3.1.0-3.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jaxb-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jaxb-core-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jaxb-jxc-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jaxb-runtime-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jaxb-xjc-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jberet-2.1.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-jberet-core-2.1.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2024-1102']},
      {'reference':'eap8-jboss-cert-helper-1.1.2-1.redhat_00001.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jboss-ejb-client-5.0.6-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jboss-modules-2.1.4-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jgroups-5.2.23-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jgroups-kubernetes-2.0.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-joda-time-2.12.5-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-jose4j-0.9.3-2.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-log4j2-jboss-logmanager-1.1.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-analyzers-common-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-core-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-facet-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-join-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-queries-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-queryparser-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-lucene-solr-8.11.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-jbosstxbridge-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-jbossxts-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-jts-idlj-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-jts-integration-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-restat-api-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-restat-bridge-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-restat-integration-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-narayana-restat-util-6.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-buffer-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-codec-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-codec-dns-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-codec-http-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-codec-socks-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-common-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-handler-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-handler-proxy-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-resolver-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-resolver-dns-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-transport-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-transport-classes-epoll-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-transport-native-epoll-4.1.100-5.Final_redhat_00001.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-netty-transport-native-unix-common-4.1.100-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-protostream-4.6.5-4.Final_redhat_00006.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-reactive-streams-1.0.4-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-relaxng-datatype-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-atom-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-cdi-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-client-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-client-api-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-core-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-core-spi-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-crypto-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-jackson2-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-jaxb-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-jsapi-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-json-binding-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-json-p-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-multipart-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-rxjava2-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-resteasy-validator-provider-6.2.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-rngom-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-slf4j-2.0.7-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-slf4j-api-2.0.7-3.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-snakeyaml-2.0.0-2.redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-stax2-api-4.2.1-2.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-sun-istack-commons-4.1.2-1.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-txw2-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-velocity-2.3.0-2.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-velocity-engine-core-2.3.0-2.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-8.0.2-2.GA_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-elytron-2.2.4-2.SP01_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2023-6236', 'CVE-2024-1233']},
      {'reference':'eap8-wildfly-elytron-tool-2.2.4-2.SP01_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503', 'CVE-2023-6236', 'CVE-2024-1233']},
      {'reference':'eap8-wildfly-http-client-common-2.0.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-http-ejb-client-2.0.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-http-naming-client-2.0.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-http-transaction-client-2.0.7-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-java-jdk11-8.0.2-2.GA_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-java-jdk17-8.0.2-2.GA_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-modules-8.0.2-2.GA_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wildfly-transaction-client-3.0.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-woodstox-core-6.4.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-ws-commons-XmlSchema-2.3.0-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wsdl4j-1.6.3-4.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-bindings-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-policy-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-ws-security-common-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-ws-security-dom-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-ws-security-policy-stax-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-wss4j-ws-security-stax-3.0.1-2.redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-xsom-4.0.2-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']},
      {'reference':'eap8-yasson-3.0.3-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2023-4503']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap8-activemq-artemis / eap8-activemq-artemis-cli / etc');
}
