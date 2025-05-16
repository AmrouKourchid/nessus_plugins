#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0946. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63988);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2011-2196");
  script_bugtraq_id(48716);
  script_xref(name:"RHSA", value:"2011:0946");
  script_xref(name:"IAVB", value:"2011-B-0086");

  script_name(english:"RHEL 6 : JBoss Enterprise Application Platform 5.1.1 update (Important) (RHSA-2011:0946)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2011:0946 advisory.

    JBoss Enterprise Application Platform is the market-leading platform for
    innovative and scalable Java applications. JBoss Enterprise Application
    Platform integrates the JBoss Application Server with JBoss Hibernate and
    JBoss Seam into a complete and simple enterprise solution.

    This JBoss Enterprise Application Platform 5.1.1 release for Red Hat
    Enterprise Linux 6 serves as a replacement for JBoss Enterprise Application
    Platform 5.1.0.

    These updated packages include the bug fixes detailed in the release notes,
    which are linked to from the References section of this erratum.

    The following security issue is also fixed with this release:

    It was found that the fix for CVE-2011-1484 was incomplete: JBoss Seam 2
    did not block access to all malicious JBoss Expression Language (EL)
    constructs in page exception handling, allowing arbitrary Java methods to
    be executed. A remote attacker could use this flaw to execute arbitrary
    code via a specially-crafted URL provided to certain applications based on
    the JBoss Seam 2 framework. Note: A properly configured and enabled Java
    Security Manager would prevent exploitation of this flaw. (CVE-2011-2196)

    Red Hat would like to thank the ObjectWorks+ Development Team at Nomura
    Research Institute for reporting this issue.

    Warning: Before applying this update, please back up your JBoss Enterprise
    Application Platform's jboss-as/server/[PROFILE]/deploy/ directory, along
    with all other customized configuration files.

    All users of JBoss Enterprise Application Platform 5.1.0 on Red Hat
    Enterprise Linux 6 are advised to upgrade to these updated packages. Manual
    action is required for this update to take effect. Refer to the Solution
    section for details.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_0946.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ca3c6d9");
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/5/html-single/Release_Notes_5.1.1/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13278f1f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=712283");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0946");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-james");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avalon-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avalon-logkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dtdparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facelets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jstl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-trove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-jopr-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:i18nlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:isorelax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-digester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aspects-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aspects-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-cache-jbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-current-invocation-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-endpoint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-endpoint-deployer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-interceptors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-jpa-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-mc-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metrics-deployer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-clustered");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timerservice-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs-impl-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jca-1.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jpa-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-mdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-microcontainer2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-reflect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-specs-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-messaging511");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-native");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:joesnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:juddi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:msv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:msv-xsdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mx4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org-mc4j-ems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-root");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servletapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snmptrapappender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-sjsxp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:werken-xpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-axiom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-scout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wstx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.1-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.2-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.3-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/6/6Server/i386/jbeap/5/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/5/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'antlr-2.7.7-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'apache-cxf-2.2.12-3.patch_01.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'apache-james-0.6-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'avalon-framework-4.1.5-2.2.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'avalon-logkit-1.2-8.2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'bcel-5.2-9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'bsf-2.4.0-4.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'bsh-1.3.0-15.5.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'bsh2-2.0-0.b4.13.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'bsh2-bsf-2.0-0.b4.13.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'cglib-2.2-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-jackson-1.3.5-0.1.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-jackson-core-asl-1.3.5-0.1.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-jackson-jaxrs-1.3.5-0.1.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-jackson-mapper-asl-1.3.5-0.1.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-stax-1.2.0-10.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'codehaus-stax-api-1.2.0-10.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'concurrent-1.3.4-10.1.5_jboss_update1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'dom4j-1.6.1-11.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'dtdparser-1.21-6.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'ecj3-3.3.1.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'facelets-1.1.15-1.B1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-jaf-1.1.0-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-javamail-1.4.2-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-jaxb-2.1.12-9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-jaxws-2.1.7-0.30.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-jsf-1.2_13-3.1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'glassfish-jstl-1.2.0-12.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'gnu-getopt-1.0.13-1.1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'gnu-trove-1.0.2-7.1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-3.3.2-1.8.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'hibernate3-annotations-3.4.0-3.5.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-annotations-javadoc-3.4.0-3.5.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-commons-annotations-3.1.0-1.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-commons-annotations-javadoc-3.1.0-1.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-1.0.2-3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'hibernate3-ejb-persistence-3.0-api-javadoc-1.0.2-3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'hibernate3-entitymanager-3.4.0-4.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-entitymanager-javadoc-3.4.0-4.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-javadoc-3.3.2-1.8.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'hibernate3-search-3.1.1-2.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-search-javadoc-3.1.1-2.4.GA_CP04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-validator-3.1.0-1.5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hibernate3-validator-javadoc-3.1.0-1.5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hornetq-jopr-plugin-2.0.0-1.Final.2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'hsqldb-1.8.0.10-9_patch_01.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'i18nlog-1.0.10-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'isorelax-0-0.4.release20050331.2.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jacorb-jboss-2.3.1-9.patch02.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-beanutils-1.8.0-9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-codec-1.3-12.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-collections-3.2.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-collections-tomcat5-3.2.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-dbcp-1.2.1-16.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-dbcp-tomcat5-1.2.1-16.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-digester-1.8.1-8.1.1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-discovery-0.4-7.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jakarta-commons-el-1.0-19.2.1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-httpclient-3.1-1.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jakarta-commons-io-1.4-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-lang-2.4-1.3.1.1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-logging-1.1.1-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-logging-jboss-1.1-10.2.2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-parent-11-2.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-pool-1.3-15.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-commons-pool-tomcat5-1.3-15.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jakarta-oro-2.0.8-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'javassist-3.12.0-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jaxbintros-1.0.0-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jaxen-1.1.2-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-aop2-2.1.6-1.CP02.1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-aspects-build-1.0.1-0.CR5.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-aspects-common-1.0.0-0.b1.1.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-bootstrap-1.0.1-2.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cache-core-3.2.7-5.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cache-pojo-3.0.0-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cl-2.0.9-1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cluster-ha-client-1.1.1-1.3.1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cluster-ha-server-api-1.2.0-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cluster-ha-server-cache-jbc-2.0.3-1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-cluster-ha-server-cache-spi-2.0.0-2.3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-common-core-2.2.17-1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-common-logging-jdk-2.1.2-1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-common-logging-log4j-2.1.2-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-common-logging-spi-2.1.2-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-current-invocation-aspects-1.0.1-1.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-deployers-2.0.10-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-eap5-native-5.1.1-3.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-eap5-native-5.1.1-3.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb-3.0-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-build-1.0.13-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-cache-1.0.0-3.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-common-1.0.2-0.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-context-0.1.1-0.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-context-base-0.1.1-0.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-context-naming-0.1.1-0.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-core-1.3.7-0.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-deployers-1.1.4-0.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-endpoint-0.1.0-2.4.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-endpoint-deployer-0.1.4-1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-ext-api-1.0.0-3.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-ext-api-impl-1.0.0-3.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-interceptors-1.0.7-0.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-jpa-int-1.0.0-1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-mc-int-1.0.2-1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-metadata-1.0.0-2.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-metrics-deployer-1.1.0-0.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-proxy-clustered-1.0.3-1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-proxy-impl-1.0.6-2.SP1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-proxy-spi-1.0.0-1.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-security-1.0.2-0.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-timeout-0.1.1-0.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-timeout-3.0-api-0.1.1-0.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-timeout-spi-0.1.1-0.7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-timerservice-spi-1.0.4-0.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-transactions-1.0.2-1.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-vfs-1.0.0-0.alpha1.0.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-vfs-impl-vfs2-1.0.0-0.alpha1.0.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-ejb3-vfs-spi-1.0.0-0.alpha1.0.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-el-1.0_02-0.CR5.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-integration-5.1.0-2.SP1.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jacc-1.1-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jad-1.2-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jaspi-1.0-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-javaee-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-javaee-poms-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jaxr-2.0.1-7.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jaxrpc-api_1.1_spec-1.0.0-15.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jca-1.5-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jms-1.1-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-jpa-deployers-1.0.0-1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-logbridge-1.0.1-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-logmanager-1.1.2-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-man-2.1.1-4.SP2.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-mdr-2.0.3-1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-messaging-1.4.8-6.SP1.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-metadata-1.0.6-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-microcontainer2-2.0.10-5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-naming-5.0.3-2.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-parent-4.0-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-reflect-2.0.3-7.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-remoting-2.5.4-8.SP2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-remoting-aspects-1.0.3-0.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-seam-int-5.1.0-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-seam2-2.2.4.EAP5-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-seam2-docs-2.2.4.EAP5-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-seam2-examples-2.2.4.EAP5-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-seam2-runtime-2.2.4.EAP5-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-security-aspects-1.0.0-2.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-security-negotiation-2.0.3-2.SP3.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-security-spi-2.0.4-5.SP7.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jboss-security-xacml-2.0.5-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-serialization-1.0.5-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-specs-parent-1.0.0-0.3.Beta2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-threads-1.0.0-2.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-transaction-aspects-1.0.0-1.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-vfs2-2.2.0-4.SP1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-xnio-base-1.2.1-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss-xnio-metadata-1.0.1-1.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jboss5-libs-5.1.0-1.6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossas-5.1.1-17.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossas-client-5.1.1-17.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossas-messaging511-5.1.1-17.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossas-ws-cxf-5.1.1-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossas-ws-native-5.1.1-17.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbosssx2-2.0.4-5.SP7.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossts-4.6.1-10.CP11_patch_01.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jbossts-javadoc-4.6.1-10.CP11_patch_01.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'jbossweb-2.1.11-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossweb-el-1.0-api-2.1.11-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossweb-jsp-2.1-api-2.1.11-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossweb-lib-2.1.11-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossweb-servlet-2.5-api-2.1.11-5.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossws-3.1.2-6.SP10.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossws-common-1.1.0-3.SP7.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossws-framework-3.1.2-5.SP9.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossws-parent-1.0.8-2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossws-spi-1.1.2-4.SP6.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jbossxb2-2.0.1-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jcip-annotations-1.0-2.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jcommon-1.0.16-1.2.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jdom-1.1.1-2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jettison-1.2-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jfreechart-1.0.13-2.3.2.1.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jgroups-2.6.19-2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'joesnmp-0.3.4-3.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jopr-embedded-1.3.4-17.SP4.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jopr-hibernate-plugin-3.0.0-11.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jopr-jboss-as-5-plugin-3.0.0-10.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jopr-jboss-cache-v3-plugin-3.0.0-9.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'juddi-2.0.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'jyaml-1.3-3.3.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'log4j-1.2.14-18.2.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-demo-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-jbossas-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-jbossweb2-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_cluster-tomcat6-1.0.10-2.2.GA_CP01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mod_jk-ap20-1.2.31-1.1.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'msv-1.2-0.20050722.10.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'msv-xsdlib-1.2-0.20050722.10.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'mx4j-3.0.1-12.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap5'},
      {'reference':'netty-3.2.3-5.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'objectweb-asm31-3.1-12.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'org-mc4j-ems-1.2.15.1-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'quartz-1.5.2-6.6.patch01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'regexp-1.5-5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'relaxngDatatype-1.0-2.4.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'resteasy-1.2.1-8.CP01.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'resteasy-examples-1.2.1-8.CP01.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'resteasy-javadoc-1.2.1-8.CP01.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'resteasy-manual-1.2.1-8.CP01.8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rh-eap-docs-5.1.1-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rh-eap-docs-examples-5.1.1-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-ant-bundle-common-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-common-parent-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-client-api-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-comm-api-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-dbutils-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-domain-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-gui-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-native-system-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-parent-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-plugin-api-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-plugin-container-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-plugindoc-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-core-util-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-filetemplate-bundle-common-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-helpers-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-jboss-as-common-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-jmx-plugin-3.0.0-15.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-modules-parent-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-parent-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-platform-plugin-3.0.0-12.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-plugin-validator-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-pluginAnnotations-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-pluginGen-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-plugins-parent-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'rhq-rtfilter-3.0.0-17.EmbJopr3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'richfaces-3.3.1-1.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'richfaces-demo-3.3.1-1.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'richfaces-framework-3.3.1-1.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'richfaces-root-3.3.1-1.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'richfaces-ui-3.3.1-1.SP3.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'scannotation-1.0.2-3.2.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'servletapi4-4.0.4-6.2.1.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'slf4j-1.5.8-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'slf4j-jboss-logging-1.0.3-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'snmptrapappender-1.2.8-8.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-agent-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-aop-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-beans-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-context-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'spring2-core-2.5.6-8.SEC02.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'stax-ex-1.2-11.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-fi-1.2.7-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-saaj-1.3-api-1.3-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-sjsxp-1.0.1-5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-ws-metadata-2.0-api-1.0.MR1-11.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-xmlstreambuffer-0.8-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'sun-xsom-20070515-4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'tomcat-native-1.1.20-2.1.2.ep5.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'tomcat-native-1.1.20-2.1.2.ep5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'velocity-1.6.3-1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'werken-xpath-0.9.4-4.beta.13.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'ws-commons-axiom-1.2.7-3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'ws-commons-neethi-2.0.4-1.2.2.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'ws-commons-XmlSchema-1.4.5-2.4.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'ws-scout-1.1.1-3.4.3.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'wsdl4j16-1.6.2-7.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'wss4j-1.5.10-3_patch_01.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'wstx-3.2.9-1.5.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xalan-j2-2.7.1-5.3_patch_04.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xerces-j2-2.9.1-8.patch01.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xerces-j2-scripts-2.9.1-8.patch01.1.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-jaxp-1.1-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-jaxp-1.2-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-jaxp-1.3-apis-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-resolver10-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-resolver11-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-resolver12-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-which10-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-commons-which11-1.3.04-7.14.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'},
      {'reference':'xml-security-1.4.3-6.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'antlr / apache-cxf / apache-james / avalon-framework / etc');
}
