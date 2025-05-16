#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0115-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233985);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id(
    "CVE-2025-3066",
    "CVE-2025-3067",
    "CVE-2025-3068",
    "CVE-2025-3069",
    "CVE-2025-3070",
    "CVE-2025-3071",
    "CVE-2025-3072",
    "CVE-2025-3073",
    "CVE-2025-3074"
  );

  script_name(english:"openSUSE 15 Security Update : chromium, gn (openSUSE-SU-2025:0115-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0115-1 advisory.

    Changes in chromium:
    - Chromium 135.0.7049.52 (stable release 2025-04-01) (boo#1240555)
      * CVE-2025-3066: Use after free in Navigations
      * CVE-2025-3067: Inappropriate implementation in Custom Tabs
      * CVE-2025-3068: Inappropriate implementation in Intents
      * CVE-2025-3069: Inappropriate implementation in Extensions
      * CVE-2025-3070: Insufficient validation of untrusted input in Extensions
      * CVE-2025-3071: Inappropriate implementation in Navigations
      * CVE-2025-3072: Inappropriate implementation in Custom Tabs
      * CVE-2025-3073: Inappropriate implementation in Autofill
      * CVE-2025-3074: Inappropriate implementation in Downloads

    Changes in gn:
    - Update to version 0.20250306:
      * Remove deps from rust executable to module's pcm files
      * Update test for rust executable deps
      * Add toolchain for cxx modules in TestWithScope
      * Apply the latest clang-format
      * Update reference for {rustdeps}
      * Always generate a .toolchain file even if it is empty.
      * Pass --with-lg-page=16 when building jemalloc for arm64.
      * Remove obsolete debug checks.
      * Make default vs ide version on Windows as 2022
      * Reland 'Adds a path_exists() function'
      * Revert 'Adds a path_exists() function'
      * Adds a path_exists() function
      * Revert 'Speed-up GN with custom OutputStream interface.'
      * Speed-up GN with custom OutputStream interface.
      * Add `exec_script_allowlist` to replace `exec_script_whitelist`.
      * Retry ReplaceFile in case of failure
      * Fix crash when NinjaBuildWriter::RunAndWriteFile fails
      * fix include for escape.h
      * fix exit code for gn gen failure
      * misc: Use html.escape instead of cgi.escape
      * Do not copy parent build_dependency_files_ in Scope constructors.
      * Improve error message for duplicated items
      * [rust-project] Always use forward slashes in sysroot paths
      * Update all_dependent_configs docs.
      * set 'no_stamp_files' by default
      * fix a typo
      * Stop using transitional LFS64 APIs
      * do not use tool prefix for phony rule
      * [rust] Add sysroot_src to rust-project.json
      * Implement and enable 'no_stamp_files'
      * Add Target::dependency_output_alias()
      * Add 'outputs' to generated_file documentation.
      * Update bug database link.
      * remove a trailing space after variable bindings
      * fix tool name in error
      * remove unused includes
      * Markdown optimization (follow-up)
      * Support link_output, depend_output in Rust linked tools.
      * Properly verify runtime_outputs in rust tool definitions.
      * BugFix: Syntax error in gen.py file
      * generated_file: add output to input deps of stamp
      * Markdown optimization:
      * Revert 'Rust: link_output, depend_output and runtime_outputs for dylibs'
      * hint using nogncheck on disallowed includes

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240555");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q43DSNVGBXKUV4FSO2HJ4XARMZYOEIFU/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7cba5a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3074");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver, chromium and / or gn packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3066");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-3069");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-135.0.7049.52-bp156.2.102.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-135.0.7049.52-bp156.2.102.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-135.0.7049.52-bp156.2.102.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-135.0.7049.52-bp156.2.102.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gn-0.20250306-bp156.2.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium / gn');
}
