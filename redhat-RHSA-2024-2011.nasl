#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:2011. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193760);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id("CVE-2023-38545");
  script_xref(name:"RHSA", value:"2024:2011");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"RHEL 6 / 7 / 8 / 9 : Satellite Client Async Security Update (Important) (RHSA-2024:2011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 / 8 / 9 host has a package installed that is affected by a vulnerability as
referenced in the RHSA-2024:2011 advisory.

    Red Hat Satellite is a system management solution that allows organizations
    to configure and maintain their systems without the necessity to provide
    public Internet access to their servers or other client systems. It
    performs provisioning and configuration management of predefined standard
    operating environments.

    Security fix:
    * puppet-agent: curl heap based buffer overflow in the SOCKS5 proxy handshake (CVE-2023-38545)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_2011.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?782d3654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241933");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2011");
  script_set_attribute(attribute:"solution", value:
"Update the affected puppet-agent package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7','8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x / 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-client/6/debug',
      'content/dist/layered/rhel8/x86_64/sat-client/6/os',
      'content/dist/layered/rhel8/x86_64/sat-client/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-7.27.0-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-client-2/6/debug',
      'content/dist/layered/rhel9/x86_64/sat-client-2/6/os',
      'content/dist/layered/rhel9/x86_64/sat-client-2/6/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-client/6/debug',
      'content/dist/layered/rhel9/x86_64/sat-client/6/os',
      'content/dist/layered/rhel9/x86_64/sat-client/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-7.27.0-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/sat-client/6/debug',
      'content/dist/rhel/client/7/7Client/x86_64/sat-client/6/os',
      'content/dist/rhel/client/7/7Client/x86_64/sat-client/6/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-client/6/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-client/6/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-client/6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sat-client/6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sat-client/6/os',
      'content/dist/rhel/server/7/7Server/x86_64/sat-client/6/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-client/6/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-client/6/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-client/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-7.27.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/els/rhel/server/6/6Server/i386/sat-client/6/debug',
      'content/els/rhel/server/6/6Server/i386/sat-client/6/os',
      'content/els/rhel/server/6/6Server/i386/sat-client/6/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/sat-client/6/debug',
      'content/els/rhel/server/6/6Server/x86_64/sat-client/6/os',
      'content/els/rhel/server/6/6Server/x86_64/sat-client/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-7.27.0-1.el6sat', 'cpu':'i686', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'puppet-agent-7.27.0-1.el6sat', 'cpu':'x86_64', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'puppet-agent');
}
