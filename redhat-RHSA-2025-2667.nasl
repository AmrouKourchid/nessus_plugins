#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:2667. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232799);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/15");

  script_cve_id("CVE-2025-24070");
  script_xref(name:"RHSA", value:"2025:2667");

  script_name(english:"RHEL 8 : .NET 9.0 (RHSA-2025:2667)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:2667 advisory.

    .NET is a managed-software framework. It implements a subset of the .NET framework APIs and several new
    APIs, and it includes a CLR implementation.

    New versions of .NET that address a security vulnerability are now available. The updated versions are
    .NET SDK 9.0.104 and .NET Runtime 9.0.3.Security Fix(es):

    * dotnet: Privilege Escalation Vulnerability in .NET SignInManager.RefreshSignInAsync Method
    (CVE-2025-24070)

    Bug Fix(es) and Enhancement(s):

    * dotnet: Privilege Escalation Vulnerability in .NET SignInManager.RefreshSignInAsync Method (BZ#2349733)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349733");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_2667.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?703f8b44");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:2667");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(269);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aspnetcore-runtime-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aspnetcore-runtime-dbg-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aspnetcore-targeting-pack-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-apphost-pack-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-hostfxr-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-runtime-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-runtime-dbg-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-9.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-aot-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-dbg-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-targeting-pack-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-templates-9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netstandard-targeting-pack-2.1");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/appstream/debug',
      'content/dist/rhel8/8.10/aarch64/appstream/os',
      'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/appstream/debug',
      'content/dist/rhel8/8.10/x86_64/appstream/os',
      'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/appstream/debug',
      'content/dist/rhel8/8.6/aarch64/appstream/os',
      'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/appstream/debug',
      'content/dist/rhel8/8.6/x86_64/appstream/os',
      'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/appstream/debug',
      'content/dist/rhel8/8.8/aarch64/appstream/os',
      'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/appstream/debug',
      'content/dist/rhel8/8.8/x86_64/appstream/os',
      'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/appstream/debug',
      'content/dist/rhel8/8.9/aarch64/appstream/os',
      'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/appstream/debug',
      'content/dist/rhel8/8.9/x86_64/appstream/os',
      'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/appstream/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/appstream/os',
      'content/public/ubi/dist/ubi8/8/aarch64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/appstream/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/appstream/os',
      'content/public/ubi/dist/ubi8/8/x86_64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'aspnetcore-runtime-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'aspnetcore-runtime-dbg-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'aspnetcore-targeting-pack-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-apphost-pack-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-host-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-hostfxr-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-runtime-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-runtime-dbg-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-sdk-9.0-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-sdk-9.0-source-built-artifacts-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-sdk-aot-9.0-9.0.104-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-sdk-aot-9.0-9.0.104-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-sdk-dbg-9.0-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-targeting-pack-9.0-9.0.3-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'dotnet-templates-9.0-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netstandard-targeting-pack-2.1-9.0.104-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aspnetcore-runtime-9.0 / aspnetcore-runtime-dbg-9.0 / etc');
}
