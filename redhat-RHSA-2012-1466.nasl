#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1466. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62931);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2012-0547",
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-1682",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4820",
    "CVE-2012-4822",
    "CVE-2012-4823",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5089",
    "CVE-2013-1475"
  );
  script_bugtraq_id(
    53951,
    55336,
    55339,
    55495,
    56025,
    56033,
    56039,
    56043,
    56046,
    56051,
    56054,
    56055,
    56056,
    56057,
    56058,
    56059,
    56061,
    56063,
    56065,
    56070,
    56071,
    56072,
    56075,
    56079,
    56080,
    56081,
    56082,
    56083
  );
  script_xref(name:"RHSA", value:"2012:1466");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-ibm (RHSA-2012:1466)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.6.0-ibm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2012:1466 advisory.

    IBM Java SE version 6 includes the IBM Java Runtime Environment and the IBM
    Java Software Development Kit.

    This update fixes several vulnerabilities in the IBM Java Runtime
    Environment and the IBM Java Software Development Kit. Detailed
    vulnerability descriptions are linked from the IBM Security alerts page,
    listed in the References section. (CVE-2012-0547, CVE-2012-1531,
    CVE-2012-1532, CVE-2012-1533, CVE-2012-1682, CVE-2012-3143, CVE-2012-3159,
    CVE-2012-3216, CVE-2012-4820, CVE-2012-4822, CVE-2012-4823, CVE-2012-5068,
    CVE-2012-5069, CVE-2012-5071, CVE-2012-5072, CVE-2012-5073, CVE-2012-5075,
    CVE-2012-5079, CVE-2012-5081, CVE-2012-5083, CVE-2012-5084, CVE-2012-5089)

    All users of java-1.6.0-ibm are advised to upgrade to these updated
    packages, containing the IBM Java SE 6 SR12 release. All running instances
    of IBM Java must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2012/rhsa-2012_1466.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23ce870e");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/developerworks/java/jdk/alerts/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:1466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=853097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=853228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=865568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=867193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=876386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=876388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=876389");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.6.0-ibm package based on the guidance in RHSA-2012:1466.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1475");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-5081");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/i386/supplementary/debug',
      'content/dist/rhel/client/5/5Client/i386/supplementary/os',
      'content/dist/rhel/client/5/5Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/os',
      'content/dist/rhel/client/5/5Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/supplementary/debug',
      'content/dist/rhel/power/5/5Server/ppc/supplementary/os',
      'content/dist/rhel/power/5/5Server/ppc/supplementary/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/supplementary/debug',
      'content/dist/rhel/server/5/5Server/i386/supplementary/os',
      'content/dist/rhel/server/5/5Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/os',
      'content/dist/rhel/server/5/5Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/5/5Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/5/5Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/supplementary/debug',
      'content/dist/rhel/workstation/5/5Client/i386/supplementary/os',
      'content/dist/rhel/workstation/5/5Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-accessibility-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-accessibility-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-accessibility-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-accessibility-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-plugin-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-plugin-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-plugin-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/supplementary/debug',
      'content/dist/rhel/client/6/6Client/i386/supplementary/os',
      'content/dist/rhel/client/6/6Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/os',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/6/6Server/ppc64/supplementary/os',
      'content/dist/rhel/power/6/6Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/supplementary/debug',
      'content/dist/rhel/server/6/6Server/i386/supplementary/os',
      'content/dist/rhel/server/6/6Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/os',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/6/6Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-demo-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-javacomm-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-jdbc-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-plugin-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-plugin-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-src-1.6.0.12.0-1jpp.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.6.0-ibm / java-1.6.0-ibm-accessibility / java-1.6.0-ibm-demo / etc');
}
