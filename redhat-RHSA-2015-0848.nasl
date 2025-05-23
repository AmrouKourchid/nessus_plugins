#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0848. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(112239);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2014-3586",
    "CVE-2014-8111",
    "CVE-2015-0226",
    "CVE-2015-0227",
    "CVE-2015-0277",
    "CVE-2015-0298",
    "CVE-2015-6254"
  );
  script_bugtraq_id(74265, 74266, 74393);
  script_xref(name:"RHSA", value:"2015:0848");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 6.4.0 update (Important) (RHSA-2015:0848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:0848 advisory.

    Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
    applications based on JBoss Application Server 7.

    It was found that a prior countermeasure in Apache WSS4J for
    Bleichenbacher's attack on XML Encryption (CVE-2011-2487) threw an
    exception that permitted an attacker to determine the failure of the
    attempted attack, thereby leaving WSS4J vulnerable to the attack.
    The original flaw allowed a remote attacker to recover the entire plain
    text form of a symmetric key. (CVE-2015-0226)

    A flaw was found in the way PicketLink's Service Provider and Identity
    Provider handled certain requests. A remote attacker could use this flaw to
    log to a victim's account via PicketLink. (CVE-2015-0277)

    It was discovered that a JkUnmount rule for a subtree of a previous JkMount
    rule could be ignored. This could allow a remote attacker to potentially
    access a private artifact in a tree that would otherwise not be accessible
    to them. (CVE-2014-8111)

    It was found that Apache WSS4J permitted bypass of the
    requireSignedEncryptedDataElements configuration property via XML Signature
    wrapping attacks. A remote attacker could use this flaw to modify the
    contents of a signed request. (CVE-2015-0227)

    It was found that the Command Line Interface, as provided by Red Hat
    Enterprise Application Platform, created a history file named
    .jboss-cli-history in the user's home directory with insecure default file
    permissions. This could allow a malicious local user to gain information
    otherwise not accessible to them. (CVE-2014-3586)

    The CVE-2015-0277 issue was discovered by Ondrej Kotek of Red Hat.

    This release of JBoss Enterprise Application Platform also includes bug
    fixes and enhancements. Documentation for these changes will be available
    shortly from the JBoss Enterprise Application Platform 6.4.0 Release Notes,
    linked to in the References.

    All users who require JBoss Enterprise Application Platform 6.4.0 on Red
    Hat Enterprise Linux 7 should install these new packages. The JBoss server
    process must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/site/documentation/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f636a44");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_0848.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e416bf1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:0848");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1126687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1155446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1158979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1165221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1165229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1167398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1167920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1167927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1183000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1188994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1194832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1195952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1198251");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6254");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(305, 327, 345, 358, 732);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-apache-commons-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-cal10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap6-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf12-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-beanvalidation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-jpa-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpclient-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-project-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcore-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpmime-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpserver");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-framework-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-annotations-api_1.1_spec");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-classfilewriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-connector-api_1.6_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-api_3.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-iiop-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-interceptors-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-j2eemgmt-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxb-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrs-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsp-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-osgi-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-rmi-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-servlet-api_2.5_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-servlet-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-weld-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.enterprise-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:staxmapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-cdi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver-eap6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-commons-daemon-eap6-1.0.15-8.redhat_1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'apache-commons-io-eap6-2.1.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-lang-eap6-2.6.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-commons-pool-eap6-1.6.0-1.redhat_7.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'apache-mime4j-0.6.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'atinject-eap6-1.0.0-1.redhat_5.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-1.9.9-10.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-core-asl-1.9.9-10.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-jaxrs-1.9.9-10.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-mapper-asl-1.9.9-10.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'codehaus-jackson-xc-1.9.9-10.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-apache-commons-cli-1.2.0-1.redhat_8.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-apache-commons-codec-1.4.0-4.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-apache-commons-configuration-1.6.0-1.redhat_4.2.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-avro-1.7.5-2.redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-cal10n-0.7.7-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-ecj-4.4.2-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-jandex-1.2.2-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-jansi-1.9.0-1.redhat_5.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-joda-time-1.6.2-2.redhat_5.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-rngom-201103.0.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'eap6-snakeyaml-1.8.0-1.redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'glassfish-jaf-1.1.1-17.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'glassfish-javamail-1.4.5-2.redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'glassfish-jsf-eap6-2.1.28-7.redhat_8.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'glassfish-jsf12-eap6-1.2.15-8.b01_redhat_12.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate-beanvalidation-api-1.0.0-5.GA_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate-jpa-2.0-api-1.0.1-6.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate3-commons-annotations-4.0.2-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-core-eap6-4.2.18-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-eap6-4.2.18-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-entitymanager-eap6-4.2.18-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-envers-eap6-4.2.18-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-infinispan-eap6-4.2.18-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-search-4.6.0-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hibernate4-validator-4.3.2-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-2.3.25-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-native-2.3.25-3.Final_redhat_1.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'hornetq-native-2.3.25-3.Final_redhat_1.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpclient-eap6-4.3.6-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-client-eap6-4.3.6-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-core-eap6-4.3.3-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcomponents-project-eap6-7.0.0-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpcore-eap6-4.3.3-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-2.2.26-38.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-2.2.26-38.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-devel-2.2.26-38.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-devel-2.2.26-38.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-manual-2.2.26-38.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-manual-2.2.26-38.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-tools-2.2.26-38.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-tools-2.2.26-38.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpmime-eap6-4.3.6-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpserver-1.0.4-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-5.2.11-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-cachestore-jdbc-5.2.11-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-cachestore-remote-5.2.11-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-client-hotrod-5.2.11-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'infinispan-core-5.2.11-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-api-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-impl-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-common-spi-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-api-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-core-impl-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-deployers-common-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-jdbc-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-spec-api-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'ironjacamar-validator-eap6-1.0.31-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'javassist-eap6-3.18.1-6.GA_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-deployment-1.3.0-5.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-framework-core-2.1.0-5.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-metadata-2.2.0-4.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-repository-2.1.0-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-resolver-3.0.1-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-spi-3.2.0-3.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbosgi-vfs-1.2.1-5.Final_redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-aesh-0.33.14-1.redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-annotations-api_1.1_spec-1.0.1-5.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-appclient-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cli-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-client-all-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-clustering-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-cmp-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-configadmin-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-connector-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-console-2.5.5-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-controller-client-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-core-security-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-repository-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-deployment-scanner-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-http-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-domain-management-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ee-deployment-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-ejb3-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-embedded-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-host-controller-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jacorb-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxr-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jaxrs-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jdr-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jmx-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jpa-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsf-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-jsr77-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-logging-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-mail-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-management-client-content-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-messaging-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-modcluster-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-naming-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-network-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-configadmin-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-osgi-service-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-picketlink-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-platform-mbean-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-pojo-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-process-controller-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-protocol-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-remoting-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-sar-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-security-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-server-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-system-jmx-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-threads-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-transactions-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-version-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-web-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-webservices-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-weld-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-as-xts-7.5.0-8.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-classfilewriter-1.0.3-3.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-common-beans-1.1.0-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-common-core-2.2.17-11.GA_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jboss-connector-api_1.6_spec-1.0.1-5.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-dmr-1.2.2-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-ejb-api_3.1_spec-1.0.2-11.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-ejb-client-1.0.30-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-genericjms-1.0.7-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-hal-2.5.5-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-iiop-client-1.0.0-5.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-interceptors-api_1.1_spec-1.0.1-6.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-j2eemgmt-api_1.1_spec-1.0.1-6.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jad-api_1.2_spec-1.0.1-7.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaspi-api_1.0_spec-1.0.1-7.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaxb-api_2.2_spec-1.0.4-4.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaxr-api_1.0_spec-1.0.2-6.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaxrpc-api_1.1_spec-1.0.1-5.Final_redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jaxrs-api_1.1_spec-1.0.1-10.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jms-api_1.1_spec-1.0.1-13.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-jsp-api_2.2_spec-1.0.2-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-logging-3.1.4-2.GA_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-logmanager-1.5.4-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-appclient-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-common-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-ear-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-ejb-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-metadata-web-7.2.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-modules-1.3.6-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-osgi-logging-1.0.0-7.redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-remote-naming-1.0.10-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-rmi-api_1.0_spec-1.0.4-10.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-sasl-1.0.5-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-seam-int-6.0.0-10.GA_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-servlet-api_2.5_spec-1.0.1-10.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-servlet-api_3.0_spec-1.0.2-4.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-threads-2.1.2-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-transaction-api_1.1_spec-1.0.1-13.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-vfs2-3.2.9-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-weld-1.1-api-1.1.0-1.Final_redhat_6.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jboss-xnio-base-3.0.13-1.GA_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-appclient-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-bundles-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-core-7.5.0-11.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-domain-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-hornetq-native-2.3.25-3.Final_redhat_1.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-hornetq-native-2.3.25-3.Final_redhat_1.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-javadocs-7.5.0-23.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-jbossweb-native-1.1.32-3.redhat_1.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-jbossweb-native-1.1.32-3.redhat_1.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-modules-eap-7.5.0-14.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-product-eap-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-standalone-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossas-welcome-content-eap-7.5.0-9.Final_redhat_21.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossts-4.17.29-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbossweb-7.5.7-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbossxb2-2.0.3-15.GA_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jcip-annotations-eap6-1.0.0-1.redhat_7.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jdom-eap6-1.1.3-1.redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jul-to-slf4j-stub-1.0.1-2.Final_redhat_2.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'log4j-jboss-logmanager-1.1.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'lucene-solr-3.6.2-5.redhat_8.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-1.2.11-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-demo-1.2.11-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.11-2.Final_redhat_2.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.11-2.Final_redhat_2.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_jk-ap22-1.2.40-3.redhat_2.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_jk-ap22-1.2.40-3.redhat_2.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_rt-2.4.1-6.GA.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_rt-2.4.1-6.GA.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_snmp-2.4.1-13.GA.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_snmp-2.4.1-13.GA.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ssl22-2.2.26-38.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_ssl22-2.2.26-38.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'objectweb-asm-eap6-3.3.1-8.redhat_9.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'org.osgi.core-eap6-4.2.0-14.redhat_8.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'org.osgi.enterprise-eap6-4.2.0-15.redhat_10.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketbox-4.1.1-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketbox-commons-1.0.0-1.final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketlink-bindings-2.5.4-5.SP4_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'picketlink-federation-2.5.4-5.SP4_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'relaxngDatatype-eap6-2011.1.0-1.redhat_9.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'resteasy-2.3.10-1.Final_redhat_1.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'staxmapper-1.1.0-7.Final_redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-codemodel-2.6.0-1.redhat_3.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-txw2-20110809.0.0-1.redhat_5.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-ws-metadata-2.0-api-1.0.0-2.MR1_redhat_7.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'sun-xsom-20110809.0.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'tomcat-native-1.1.32-3.redhat_1.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'tomcat-native-1.1.32-3.redhat_1.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'velocity-eap6-1.7.0-1.redhat_4.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'weld-cdi-1.0-api-1.0.0-1.SP4_redhat_5.1.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'xml-commons-resolver-eap6-1.2.0-1.redhat_10.2.ep6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-daemon-eap6 / apache-commons-io-eap6 / etc');
}
