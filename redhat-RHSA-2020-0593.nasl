##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0593. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134065);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2018-15686", "CVE-2018-16866");
  script_bugtraq_id(105747, 106527);
  script_xref(name:"RHSA", value:"2020:0593");

  script_name(english:"RHEL 7 : systemd (RHSA-2020:0593)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for systemd.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0593 advisory.

    The systemd packages contain systemd, a system and service manager for Linux, compatible with the SysV and
    LSB init scripts. It provides aggressive parallelism capabilities, uses socket and D-Bus activation for
    starting services, offers on-demand starting of daemons, and keeps track of processes using Linux cgroups.
    In addition, it supports snapshotting and restoring of the system state, maintains mount and automount
    points, and implements an elaborate transactional dependency-based service control logic. It can also work
    as a drop-in replacement for sysvinit.

    Security Fix(es):

    * systemd: line splitting via fgets() allows for state injection during daemon-reexec (CVE-2018-15686)

    * systemd: out-of-bounds read when parsing a crafted syslog message (CVE-2018-16866)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_0593.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22187e45");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1639071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1653867");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL systemd package based on the guidance in RHSA-2020:0593.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-sysv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.4')) audit(AUDIT_OS_NOT, 'Red Hat 7.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.4/x86_64/debug',
      'content/aus/rhel/server/7/7.4/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.4/x86_64/optional/os',
      'content/aus/rhel/server/7/7.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.4/x86_64/os',
      'content/aus/rhel/server/7/7.4/x86_64/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/debug',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/highavailability/debug',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/highavailability/os',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/optional/debug',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/optional/os',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/optional/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/os',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/source/SRPMS',
      'content/e4s/rhel/server/7/7.4/x86_64/debug',
      'content/e4s/rhel/server/7/7.4/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.4/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.4/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.4/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.4/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.4/x86_64/os',
      'content/e4s/rhel/server/7/7.4/x86_64/source/SRPMS',
      'content/tus/rhel/server/7/7.4/x86_64/debug',
      'content/tus/rhel/server/7/7.4/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.4/x86_64/optional/os',
      'content/tus/rhel/server/7/7.4/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.4/x86_64/os',
      'content/tus/rhel/server/7/7.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libgudev1-219-42.el7_4.20', 'sp':'4', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgudev1-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgudev1-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgudev1-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgudev1-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgudev1-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-devel-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-journal-gateway-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-journal-gateway-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-libs-219-42.el7_4.20', 'sp':'4', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-libs-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-libs-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-networkd-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-networkd-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-python-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-python-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-resolved-219-42.el7_4.20', 'sp':'4', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-resolved-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-resolved-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-sysv-219-42.el7_4.20', 'sp':'4', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'systemd-sysv-219-42.el7_4.20', 'sp':'4', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Advanced Update Support, Telco Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgudev1 / libgudev1-devel / systemd / systemd-devel / etc');
}
