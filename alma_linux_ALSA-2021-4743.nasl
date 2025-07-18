#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:4743.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157580);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2021-42574");
  script_xref(name:"ALSA", value:"2021:4743");
  script_xref(name:"IAVA", value:"2021-A-0528");

  script_name(english:"AlmaLinux 8 : llvm-toolset:rhel8 (ALSA-2021:4743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2021:4743 advisory.

    * Developer environment: Unicode's bidirectional (BiDi) override characters can cause trojan source
    attacks (CVE-2021-42574)

    The following changes were introduced in clang in order to facilitate detection of BiDi Unicode
    characters:

    clang-tidy now finds identifiers that contain Unicode characters with right-to-left direction, which can
    be confusing as they may change the understanding of a whole statement.

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-4743.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang-resource-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clang-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:compiler-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-clang-format");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libomp-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lld-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lld-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-googletest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:llvm-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-clang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-lit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-lldb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/llvm-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module llvm-toolset:rhel8');
if ('rhel8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module llvm-toolset:' + module_ver);

var appstreams = {
    'llvm-toolset:rhel8': [
      {'reference':'clang-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-analyzer-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-devel-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-devel-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-libs-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-libs-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-resource-filesystem-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-resource-filesystem-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-tools-extra-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clang-tools-extra-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'compiler-rt-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'compiler-rt-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'git-clang-format-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'git-clang-format-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-test-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libomp-test-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-libs-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-libs-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-test-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lld-test-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lldb-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lldb-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lldb-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lldb-devel-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-devel-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-devel-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-doc-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-googletest-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-googletest-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-libs-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-libs-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-static-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-static-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-test-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-test-12.0.1-2.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-toolset-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'llvm-toolset-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-clang-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-clang-12.0.1-4.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-lit-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-lldb-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-lldb-12.0.1-1.module_el8.4.0+2600+cefb5d4c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module llvm-toolset:rhel8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clang / clang-analyzer / clang-devel / clang-libs / etc');
}
