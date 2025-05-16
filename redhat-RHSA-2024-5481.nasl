#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5481. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205636);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2024-28752",
    "CVE-2024-29025",
    "CVE-2024-29857",
    "CVE-2024-30171",
    "CVE-2024-30172"
  );
  script_xref(name:"RHSA", value:"2024:5481");

  script_name(english:"RHEL 9 : Red Hat JBoss Enterprise Application Platform 8.0.3 Security update (Important) (RHSA-2024:5481)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:5481 advisory.

    Red Hat JBoss Enterprise Application Platform 8 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 8.0.3 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 8.0.2, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 8.0.3 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * cxf-core: Apache CXF SSRF Vulnerability using the Aegis databinding [eap-8.0.z] (CVE-2024-28752)

    * org.bouncycastle-bcprov-jdk18on: BouncyCastle vulnerable to a timing variant of Bleichenbacher (Marvin
    Attack) [eap-8.0.z] (CVE-2024-30171)

    * netty-codec-http: Allocation of Resources Without Limits or Throttling [eap-8.0.z] (CVE-2024-29025)

    * org.bouncycastle:bcprov-jdk18on: Infinite loop in ED25519 verification in the ScalarUtil class
    [eap-8.0.z] (CVE-2024-30172)

    * org.bouncycastle:bcprov-jdk18on: org.bouncycastle: Importing an EC certificate with crafted F2m
    parameters may lead to Denial of Service [eap-8.0.z] (CVE-2024-29857)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5481.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?451412fb");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/8.0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?919aa761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293028");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-25224");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26018");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26696");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26790");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26791");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26793");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26802");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26816");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26823");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26843");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26886");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26932");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26948");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26961");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26962");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26966");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26986");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27002");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27019");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27055");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27090");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27192");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27194");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27261");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27262");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27327");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-27356");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5481");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 208, 770, 835, 918);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus-activation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-angus-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-mime4j-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-mime4j-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-jmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-byte-buddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-caffeine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-bug986");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-eap-product-conf-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-eap-product-conf-wildfly-ee-feature-pack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava-failureaccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hornetq-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hornetq-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-hornetq-jakarta-client");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-json-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-servlet-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-websocket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-websocket-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-websocket-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-xml-bind-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jasypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-java-classmate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-xjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-openjdk-orb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jsf-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-neethi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-xnio-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-profile-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-security-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-security-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-soap-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xacml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xacml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xacml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xacml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xmlsec-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-opensaml-xmlsec-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-parsson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-reactivex-rxjava");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-velocity-engine-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-lite-extension-translator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-discovery-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-java-jdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wsdl4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-yasson");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
      {'reference':'eap8-activemq-artemis-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-cli-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-commons-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-core-client-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-dto-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-hornetq-protocol-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-hqclient-protocol-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-jakarta-client-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-jakarta-ra-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-jakarta-server-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-jakarta-service-extensions-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-jdbc-store-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-journal-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-selector-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-activemq-artemis-server-2.21.0-5.redhat_00052.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-angus-activation-2.0.1-3.redhat_00006.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-angus-mail-2.0.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-commons-beanutils-1.9.4-13.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-commons-cli-1.4.0-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-commons-codec-1.15.0-6.redhat_00016.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-cxf-4.0.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-cxf-rt-4.0.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-cxf-services-4.0.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-cxf-tools-4.0.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-cxf-xjc-utils-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-mime4j-0.8.11-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-mime4j-dom-0.8.11-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-mime4j-storage-0.8.11-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-apache-sshd-2.12.1-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-jmail-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-pg-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-pkix-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-prov-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-util-1.78.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-byte-buddy-1.14.18-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-caffeine-3.1.8-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-codemodel-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-cxf-xjc-boolean-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-cxf-xjc-bug986-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-cxf-xjc-dv-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-cxf-xjc-runtime-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-cxf-xjc-ts-4.0.0-5.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752', 'CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-eap-product-conf-parent-800.3.0-2.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-eap-product-conf-wildfly-ee-feature-pack-800.3.0-2.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-guava-33.0.0-1.jre_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-guava-failureaccess-1.0.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-guava-libraries-33.0.0-1.jre_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-hal-console-3.6.19-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-hornetq-2.4.9-4.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-hornetq-commons-2.4.9-4.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-hornetq-core-client-2.4.9-4.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-hornetq-jakarta-client-2.4.9-4.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-httpcomponents-asyncclient-4.1.5-3.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-httpcomponents-client-4.5.14-4.redhat_00012.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-httpcomponents-core-4.4.16-4.redhat_00010.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cachestore-jdbc-common-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cachestore-jdbc-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cachestore-remote-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cdi-common-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cdi-embedded-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-cdi-remote-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-client-hotrod-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-clustered-counter-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-clustered-lock-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-commons-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-component-annotations-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-core-jakarta-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-hibernate-cache-commons-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-hibernate-cache-spi-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-hibernate-cache-v62-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-objectfilter-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-query-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-query-core-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-query-dsl-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-infinispan-remote-query-client-14.0.30-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-json-api-2.1.3-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-mail-2.1.3-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-servlet-api-6.0.0-5.redhat_00006.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-websocket-api-2.1.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-websocket-client-api-2.1.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jakarta-xml-bind-api-4.0.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jandex-3.0.8-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jasypt-1.9.3-4.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-java-classmate-1.5.1-3.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jaxb-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jaxb-core-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jaxb-jxc-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jaxb-runtime-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jaxb-xjc-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-appclient-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-common-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-ear-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-ejb-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-metadata-web-16.0.0-3.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jboss-openjdk-orb-10.1.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jbossws-cxf-7.1.0-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-joda-time-2.12.7-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-jsf-impl-4.0.7-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-mod_cluster-2.0.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-neethi-3.2.0-1.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-buffer-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-codec-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-codec-dns-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-codec-http-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-codec-socks-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-common-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-handler-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-handler-proxy-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-resolver-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-resolver-dns-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-transport-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-transport-classes-epoll-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-transport-native-epoll-4.1.108-1.Final_redhat_00001.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-transport-native-unix-common-4.1.108-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-netty-xnio-transport-0.1.10-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-core-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-profile-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-saml-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-saml-impl-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-security-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-security-impl-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-soap-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xacml-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xacml-impl-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xacml-saml-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xacml-saml-impl-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xmlsec-api-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-opensaml-xmlsec-impl-4.2.0-4.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-parsson-1.1.5-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-reactivex-rxjava-3.1.8-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-relaxng-datatype-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-atom-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-cdi-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-client-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-client-api-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-core-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-core-spi-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-crypto-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-jackson2-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-jaxb-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-jsapi-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-json-binding-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-json-p-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-multipart-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-rxjava2-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-resteasy-validator-provider-6.2.7-2.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-rngom-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-slf4j-2.0.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-slf4j-api-2.0.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-stax2-api-4.2.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-txw2-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-velocity-2.3.0-3.redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-velocity-engine-core-2.3.0-3.redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-core-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-core-impl-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-core-jsf-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-ejb-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-jta-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-lite-extension-translator-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-weld-web-5.1.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-8.0.3-9.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-discovery-client-1.3.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-elytron-2.2.6-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-elytron-tool-2.2.6-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-java-jdk11-8.0.3-9.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-java-jdk17-8.0.3-9.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wildfly-modules-8.0.3-9.GA_redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wsdl4j-1.6.3-5.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-bindings-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-policy-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-ws-security-common-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-ws-security-dom-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-ws-security-policy-stax-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-wss4j-ws-security-stax-3.0.3-1.redhat_00008.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-xml-security-3.0.4-1.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-xsom-4.0.5-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-yasson-3.0.3-3.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025', 'CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']}
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
