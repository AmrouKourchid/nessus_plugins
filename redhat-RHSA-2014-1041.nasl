#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1041. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77142);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2014-3068",
    "CVE-2014-3086",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4265",
    "CVE-2014-4266"
  );
  script_bugtraq_id(
    68571,
    68576,
    68580,
    68583,
    68596,
    68599,
    68603,
    68620,
    68624,
    68632,
    68636,
    68639,
    68642,
    71408
  );
  script_xref(name:"RHSA", value:"2014:1041");

  script_name(english:"RHEL 5 / 6 : java-1.7.0-ibm (RHSA-2014:1041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.7.0-ibm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1041 advisory.

    IBM Java SE version 7 includes the IBM Java Runtime Environment and the IBM
    Java Software Development Kit.

    This update fixes several vulnerabilities in the IBM Java Runtime
    Environment and the IBM Java Software Development Kit. Detailed
    vulnerability descriptions are linked from the IBM Security alerts
    page, listed in the References section. (CVE-2014-4208, CVE-2014-4209,
    CVE-2014-4218, CVE-2014-4219, CVE-2014-4220, CVE-2014-4221, CVE-2014-4227,
    CVE-2014-4244, CVE-2014-4252, CVE-2014-4262, CVE-2014-4263, CVE-2014-4265,
    CVE-2014-4266)

    The CVE-2014-4262 issue was discovered by Florian Weimer of Red Hat
    Product Security.

    All users of java-1.7.0-ibm are advised to upgrade to these updated
    packages, containing the IBM Java SE 7 SR7-FP1 release. All running
    instances of IBM Java must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1041.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd991ef5");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/developerworks/java/jdk/alerts/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1075795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1119915");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.7.0-ibm package based on the guidance in RHSA-2014:1041.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4227");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-4209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
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
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-plugin-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-plugin-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-plugin-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el5_10', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-demo-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-devel-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-jdbc-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-plugin-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-plugin-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.0-ibm-src-1.7.0.7.1-1jpp.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.7.0-ibm / java-1.7.0-ibm-demo / java-1.7.0-ibm-devel / etc');
}
