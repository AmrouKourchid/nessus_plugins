#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:2332. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210310);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2017-18191");
  script_xref(name:"RHSA", value:"2018:2332");

  script_name(english:"RHEL 7 : openstack-nova (RHSA-2018:2332)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:2332 advisory.

    OpenStack Compute (nova) launches and schedules large networks of virtual
    machines, creating a redundant and scalable cloud computing platform.
    Compute provides the software, control panels, and APIs required to
    orchestrate a cloud, including running virtual machine instances and
    controlling access through users and projects.

    The following packages have been upgraded to a later upstream version:
    openstack-nova (16.1.4). (BZ#1591212)

    Security Fix(es):

    * openstack-nova: Swapping encrypted volumes can allow an attacker to corrupt the LUKS header causing a
    denial of service in the host (CVE-2017-18191)

    For more details about the security issue(s), including the impact, a CVSS
    score, and other related information, refer to the CVE page(s) listed in
    the References section.

    For more information about the bug fixes and enhancements included with this update, see the Technical
    Notes section of the Release Notes
    linked in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/12/html/release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c016032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1516271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1537047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1539703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1546937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1547578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1556851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1557938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1558706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1569955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1570314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1572836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1573799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1575985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1579785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1590514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1591212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1591296");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_2332.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2283714c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2332");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-placement-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-spicehtml5proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nova-tests");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-nova-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-api-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-cells-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-common-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-compute-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-conductor-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-console-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-migration-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-network-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-novncproxy-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-placement-api-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-scheduler-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-serialproxy-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-spicehtml5proxy-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python-nova-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python-nova-tests-16.1.4-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-nova / openstack-nova-api / openstack-nova-cells / etc');
}
