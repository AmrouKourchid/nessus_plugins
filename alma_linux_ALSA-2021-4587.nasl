#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:4587.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157722);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/10");

  script_cve_id("CVE-2021-42574");
  script_xref(name:"ALSA", value:"2021:4587");
  script_xref(name:"IAVA", value:"2021-A-0528");

  script_name(english:"AlmaLinux 8 : gcc (ALSA-2021:4587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2021:4587 advisory.

  - An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It
    permits the visual reordering of characters via control sequences, which can be used to craft source code
    that renders different logic than the logical ordering of tokens ingested by compilers and interpreters.
    Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted
    vulnerabilities are introduced invisibly to human reviewers. (CVE-2021-42574)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-4587.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libubsan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'cpp-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-4.el8_5.alma', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-4.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / gcc / gcc-c++ / gcc-gdb-plugin / gcc-gfortran / etc');
}
