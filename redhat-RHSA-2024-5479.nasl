#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5479. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205637);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2024-28752",
    "CVE-2024-29025",
    "CVE-2024-29857",
    "CVE-2024-30171",
    "CVE-2024-30172"
  );
  script_xref(name:"RHSA", value:"2024:5479");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 8.0.3 Security update (Important) (RHSA-2024:5479)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:5479 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/8.0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?919aa761");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5479.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af7e7991");
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
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-26792");
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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5479");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-jmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-bouncycastle-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-bug986");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jakarta-servlet-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jaxb-xjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-jboss-openjdk-orb");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-netty-transport-native-unix-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-relaxng-datatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-wsdl4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap8-xsom");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbeap/8.0/debug',
      'content/dist/layered/rhel8/x86_64/jbeap/8.0/os',
      'content/dist/layered/rhel8/x86_64/jbeap/8.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap8-apache-commons-beanutils-1.9.4-13.redhat_00004.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-apache-cxf-4.0.4-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-apache-cxf-rt-4.0.4-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-apache-cxf-services-4.0.4-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-apache-cxf-tools-4.0.4-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-apache-cxf-xjc-utils-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-bouncycastle-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-jmail-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-pg-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-pkix-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-prov-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-bouncycastle-util-1.78.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29857', 'CVE-2024-30171', 'CVE-2024-30172']},
      {'reference':'eap8-codemodel-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-cxf-xjc-boolean-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-cxf-xjc-bug986-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-cxf-xjc-dv-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-cxf-xjc-runtime-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-cxf-xjc-ts-4.0.0-5.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-28752']},
      {'reference':'eap8-guava-33.0.0-1.jre_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-guava-libraries-33.0.0-1.jre_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jakarta-servlet-api-6.0.0-5.redhat_00006.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jaxb-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jaxb-core-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jaxb-jxc-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jaxb-runtime-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jaxb-xjc-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-jboss-openjdk-orb-10.1.0-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-buffer-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-codec-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-codec-dns-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-codec-http-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-codec-socks-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-common-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-handler-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-handler-proxy-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-resolver-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-resolver-dns-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-transport-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-transport-classes-epoll-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-netty-transport-native-unix-common-4.1.108-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-relaxng-datatype-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-rngom-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-txw2-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-wsdl4j-1.6.3-5.redhat_00008.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']},
      {'reference':'eap8-xsom-4.0.5-2.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap8', 'cves':['CVE-2024-29025']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap8-apache-commons-beanutils / eap8-apache-cxf / etc');
}
