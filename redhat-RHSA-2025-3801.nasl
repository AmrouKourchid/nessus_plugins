#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:3801. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234263);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/13");

  script_cve_id(
    "CVE-2021-37501",
    "CVE-2024-29157",
    "CVE-2024-29158",
    "CVE-2024-29159",
    "CVE-2024-29160",
    "CVE-2024-29161",
    "CVE-2024-29162",
    "CVE-2024-29163",
    "CVE-2024-29164",
    "CVE-2024-29165",
    "CVE-2024-32605",
    "CVE-2024-32608",
    "CVE-2024-32609",
    "CVE-2024-32611",
    "CVE-2024-32612",
    "CVE-2024-32613",
    "CVE-2024-32614",
    "CVE-2024-32615",
    "CVE-2024-32616",
    "CVE-2024-32617",
    "CVE-2024-32618",
    "CVE-2024-32619",
    "CVE-2024-32620",
    "CVE-2024-32621",
    "CVE-2024-32622",
    "CVE-2024-32623",
    "CVE-2024-32624",
    "CVE-2024-33873",
    "CVE-2024-33874",
    "CVE-2024-33877"
  );
  script_xref(name:"RHSA", value:"2025:3801");

  script_name(english:"RHEL 9 : RHEL AI 1.5 hdf5 (RHSA-2025:3801)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for RHEL AI 1.5 hdf5.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:3801 advisory.

    RPM packages are internal build artifacts and not supported on their own.
    They are only supported as part of the RHEL AI application image.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/AIPCC-744");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_3801.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1241403b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3801");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL RHEL AI 1.5 hdf5 package based on the guidance in RHSA-2025:3801.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32608");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libaec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libaec-devel");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhelai-cuda/1.5/debug',
      'content/dist/layered/rhel9/aarch64/rhelai-cuda/1.5/os',
      'content/dist/layered/rhel9/aarch64/rhelai-cuda/1.5/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/rhelai/1.5/debug',
      'content/dist/layered/rhel9/aarch64/rhelai/1.5/os',
      'content/dist/layered/rhel9/aarch64/rhelai/1.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhelai-cuda/1.5/debug',
      'content/dist/layered/rhel9/x86_64/rhelai-cuda/1.5/os',
      'content/dist/layered/rhel9/x86_64/rhelai-cuda/1.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhelai-gaudi/1.5/debug',
      'content/dist/layered/rhel9/x86_64/rhelai-gaudi/1.5/os',
      'content/dist/layered/rhel9/x86_64/rhelai-gaudi/1.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhelai/1.5/debug',
      'content/dist/layered/rhel9/x86_64/rhelai/1.5/os',
      'content/dist/layered/rhel9/x86_64/rhelai/1.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'hdf5-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-devel-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-devel-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-devel-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-devel-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-static-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-openmpi-static-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-static-1.14.6-3.1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hdf5-static-1.14.6-3.1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libaec-1.1.3-1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libaec-1.1.3-1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libaec-devel-1.1.3-1.el9ai', 'cpu':'aarch64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libaec-devel-1.1.3-1.el9ai', 'cpu':'x86_64', 'release':'9', 'el_string':'el9ai', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hdf5 / hdf5-devel / hdf5-openmpi / hdf5-openmpi-devel / etc');
}
