#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:1746. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216682);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id(
    "CVE-2020-8840",
    "CVE-2020-9546",
    "CVE-2020-9547",
    "CVE-2020-9548",
    "CVE-2020-10672",
    "CVE-2020-10673",
    "CVE-2020-13936",
    "CVE-2021-3717",
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2022-1471",
    "CVE-2022-41881",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-42889",
    "CVE-2022-45047",
    "CVE-2022-45693",
    "CVE-2022-46363"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");
  script_xref(name:"RHSA", value:"2025:1746");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.1.9 on RHEL 7 (RHSA-2025:1746)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform 7.1.9
on RHEL 7.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:1746 advisory.

    Red Hat JBoss Enterprise Application Platform 7 is a platform for Java applications based on the WildFly
    application runtime. This release of Red Hat JBoss Enterprise Application Platform 7.1.9 serves as a
    replacement for Red Hat JBoss Enterprise Application Platform 7.1.8, and includes bug fixes and
    enhancements. See the Red Hat JBoss Enterprise Application Platform 7.1.9 Release Notes for information
    about the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * codec-haproxy: HAProxyMessageDecoder Stack Exhaustion DoS [eap-7.1.z] (CVE-2022-41881)

    * velocity: arbitrary code execution when attacker is able to modify templates [eap-7.1.z]
    (CVE-2020-13936)

    * jackson-databind: mishandles the interaction between serialization gadgets and typing which could result
    in remote command execution [eap-7.1.z] (CVE-2020-10673)

    * jackson-databind: Serialization gadgets in anteros-core [eap-7.1.z] (CVE-2020-9548)

    * jackson-databind: mishandles the interaction between serialization gadgets and typing which could result
    in remote command execution [eap-7.1.z] (CVE-2020-10672)

    * wildfly: incorrect JBOSS_LOCAL_USER challenge location may lead to giving access to all the local users
    [eap-7.1.z] (CVE-2021-3717)

    * jackson-databind: Serialization gadgets in ibatis-sqlmap [eap-7.1.z] (CVE-2020-9547)

    * log4j-core: DoS in log4j 2.x with thread context message pattern and context lookup pattern (incomplete
    fix for CVE-2021-44228) [eap-7.1.z] (CVE-2021-45046)

    * log4j-core: Remote code execution in Log4j 2.x when logs contain an attacker-controlled string value
    [eap-7.1.z] (CVE-2021-44228)

    * jackson-databind: Serialization gadgets in shaded-hikari-config [eap-7.1.z] (CVE-2020-9546)

    * CXF: Apache CXF: directory listing / code exfiltration [eap-7.1.z] (CVE-2022-46363)

    * sshd-common: mina-sshd: Java unsafe deserialization vulnerability [eap-7.1.z] (CVE-2022-45047)

    * jettison:  If the value in map is the map's self, the new new JSONObject(map) cause StackOverflowError
    which may lead to dos [eap-7.1.z] (CVE-2022-45693)

    * jackson-databind: deep wrapper array nesting wrt UNWRAP_SINGLE_VALUE_ARRAYS [eap-7.1.z] (CVE-2022-42003)

    * jackson-databind: use of deeply nested arrays [eap-7.1.z] (CVE-2022-42004)

    * jackson-databind: Lacks certain xbean-reflect/JNDI blocking [eap-7.1.z] (CVE-2020-8840)

    * snakeyaml: Constructor Deserialization Remote Code Execution [eap-7.1.z] (CVE-2022-1471)

    * commons-text: apache-commons-text: variable interpolation RCE [eap-7.1.z] (CVE-2022-42889)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References
    section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/7.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2684bd9c");
  # https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/7.1/html-single/installation_guide/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?690e43fa");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1815470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1815495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1816330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1816332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1816337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1816340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1991305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2030932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2032580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2145194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2150009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155970");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28583");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-28817");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_1746.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78242e2a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:1746");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 7.1.9 on RHEL 7 package based on the guidance in
RHSA-2025:1746.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Commons Text RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(20, 94, 96, 400, 502, 552, 674, 787, 1188);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/debug',
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/os',
      'content/eus/rhel/server/7/7Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-apache-cxf-3.1.16-4.redhat_00003.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-apache-cxf-rt-3.1.16-4.redhat_00003.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-apache-cxf-services-3.1.16-4.redhat_00003.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-apache-cxf-tools-3.1.16-4.redhat_00003.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-jackson-databind-2.8.11.6-2.SP1_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-jettison-1.3.8-2.redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-netty-4.1.63-1.Final_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-netty-all-4.1.63-1.Final_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-resteasy-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-atom-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-cdi-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-client-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-crypto-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jackson-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jackson2-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jaxb-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jaxrs-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jettison-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jose-jwt-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-jsapi-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-json-p-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-multipart-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-spring-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-validator-provider-11-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-resteasy-yaml-provider-3.0.27-1.Final_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-8840', 'CVE-2020-9546', 'CVE-2020-9547', 'CVE-2020-9548', 'CVE-2020-10672', 'CVE-2020-10673', 'CVE-2020-13936', 'CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42003', 'CVE-2022-42004', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693', 'CVE-2022-46363']},
      {'reference':'eap7-snakeyaml-1.33.0-1.SP1_redhat_00001.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-1471', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-velocity-1.7.0-3.redhat_00006.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2020-13936', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-wildfly-7.1.9-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']},
      {'reference':'eap7-wildfly-modules-7.1.9-2.GA_redhat_00002.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7', 'cves':['CVE-2021-3717', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-41881', 'CVE-2022-42889', 'CVE-2022-45047', 'CVE-2022-45693']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-cxf / eap7-apache-cxf-rt / eap7-apache-cxf-services / etc');
}
