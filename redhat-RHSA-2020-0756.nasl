#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0756. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170292);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2019-14846", "CVE-2019-14856", "CVE-2019-14858");
  script_xref(name:"RHSA", value:"2020:0756");

  script_name(english:"RHEL 7 : ansible (RHSA-2020:0756)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for ansible.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2020:0756 advisory.

    Ansible is a simple model-driven configuration management, multi-node deployment, and remote-task
    execution system. Ansible works over SSH and does not require any software or daemons to be installed on
    remote nodes. Extension modules can be written in any language and are transferred to managed machines
    automatically.

    Security Fix(es):

    * ansible: secrets disclosed on logs when no_log enabled (CVE-2019-14846)

    * ansible: Incomplete fix for CVE-2019-10206 (CVE-2019-14856)

    * ansible: sub parameters marked as no_log are not masked in certain failure scenarios (CVE-2019-14858)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_0756.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bc4b73d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1755373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1760593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1760829");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL ansible package based on the guidance in RHSA-2020:0756.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14856");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287, 532);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-2.6.20-1.el7ae', 'release':'7', 'el_string':'el7ae', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible');
}
