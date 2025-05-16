#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2866.
##

include('compat.inc');

if (description)
{
  script_id(176274);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-2880", "CVE-2022-41715", "CVE-2022-41717");
  script_xref(name:"IAVB", value:"2022-B-0042-S");
  script_xref(name:"IAVB", value:"2022-B-0059-S");

  script_name(english:"Oracle Linux 8 : git-lfs (ELSA-2023-2866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2023-2866 advisory.

    [3.2.0-2]
    - Rebuild with Golang-1.19.4
    - Resolves: #2163744

    [3.2.0-1]
    - Update to version 3.2.0
    - Resolves: #2139382

    [2.13.3-2]
    - Define %gobuild macro with proper ldflags
    - Related: rhbz#2021549

    [2.13.3-1]
    - Update to version 2.13.3
    - Fixed round brackets in Provides
    - Moved manpages.tgz to look-a-side cache
    - Resolves: rhbz#2021549, rhbz#1870080, rhbz#1866441

    [2.11.0-2]
    - Removed mangen source file
    - Cleaned docs/man folder
    - Resolves: rhbz#1852842

    [2.11.0-1]
    - Update to version 2.11.0
    - Resolves: rhbz#1783391

    [2.4.1-3]
    - Add pregenerated manpages, due to missing dependency 'ronn' in rhel7.

    [2.4.1-2]
    - Initial build for rh-git218-git-lfs-2.4.1

    [2.4.1-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

    [2.4.1-1]
    - Update to latest release

    [2.4.0-3]
    - Fix %preun to correctly remove the lfs filter on uninstall (rhbz#1580357)

    [2.4.0-2]
    - Add %go_arches fallback to work around Koji issues

    [2.4.0-1]
    - Update to latest release.

    [2.3.4-6]
    - Add patches to build with Go 1.10.

    [2.3.4-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [2.3.4-4]
    - Use vendored libraries on RHEL
    - Skip test on RHEL
    - Don't build man pages on RHEL due to missing ronn
    - Don't build html versions of man pages

    [2.3.4-3]
    - Require git-core instead of git.

    [2.3.4-2]
    - Patch tests to work on slow systems like arm and aarch builders.
    - Fix 'git lfs help' command.

    [2.3.4-1]
    - Update to latest release.
    - Run all tests during build.

    [2.2.1-3]
    - Remove redundant doc tag on manpages.
    - Use path macros in %post/%postun.

    [2.2.1-2]
    - Disable unnecessary subpackages.

    [2.2.1-1]
    - Update to latest version.

    [2.0.2-2]
    - Patch up to build with Go 1.7

    [2.0.2-1]
    - Update to latest release
    - Add some requested macros

    [2.0.1-1]
    - Update to latest release
    - Don't disable git-lfs globally during upgrade

    [2.0.0-1]
    - Update to latest release

    [1.5.5-1]
    - Update to latest release
    - Add -devel and -unit-test-devel subpackages
    - Add post/preun scriptlets for global enablement

    [1.2.0-1]
    - Initial package

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2866.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected git-lfs package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2880");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-lfs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'git-lfs-3.2.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-lfs-3.2.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git-lfs');
}
