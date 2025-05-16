#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0254-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206192);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/06");

  script_cve_id(
    "CVE-2024-6988",
    "CVE-2024-6989",
    "CVE-2024-6990",
    "CVE-2024-6991",
    "CVE-2024-6992",
    "CVE-2024-6993",
    "CVE-2024-6994",
    "CVE-2024-6995",
    "CVE-2024-6996",
    "CVE-2024-6997",
    "CVE-2024-6998",
    "CVE-2024-6999",
    "CVE-2024-7000",
    "CVE-2024-7001",
    "CVE-2024-7003",
    "CVE-2024-7004",
    "CVE-2024-7005",
    "CVE-2024-7255",
    "CVE-2024-7256",
    "CVE-2024-7532",
    "CVE-2024-7533",
    "CVE-2024-7534",
    "CVE-2024-7535",
    "CVE-2024-7536",
    "CVE-2024-7550"
  );

  script_name(english:"openSUSE 15 Security Update : chromium, gn, rust-bindgen (openSUSE-SU-2024:0254-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0254-2 advisory.

    - Chromium 127.0.6533.119 (boo#1228941)

      * CVE-2024-7532: Out of bounds memory access in ANGLE
      * CVE-2024-7533: Use after free in Sharing
      * CVE-2024-7550: Type Confusion in V8
      * CVE-2024-7534: Heap buffer overflow in Layout
      * CVE-2024-7535: Inappropriate implementation in V8
      * CVE-2024-7536: Use after free in WebAudio

    - Chromium 127.0.6533.88 (boo#1228628, boo#1228940, boo#1228942)

      * CVE-2024-6988: Use after free in Downloads
      * CVE-2024-6989: Use after free in Loader
      * CVE-2024-6991: Use after free in Dawn
      * CVE-2024-6992: Out of bounds memory access in ANGLE
      * CVE-2024-6993: Inappropriate implementation in Canvas
      * CVE-2024-6994: Heap buffer overflow in Layout
      * CVE-2024-6995: Inappropriate implementation in Fullscreen
      * CVE-2024-6996: Race in Frames
      * CVE-2024-6997: Use after free in Tabs
      * CVE-2024-6998: Use after free in User Education
      * CVE-2024-6999: Inappropriate implementation in FedCM
      * CVE-2024-7000: Use after free in CSS. Reported by Anonymous
      * CVE-2024-7001: Inappropriate implementation in HTML
      * CVE-2024-7003: Inappropriate implementation in FedCM
      * CVE-2024-7004: Insufficient validation of untrusted input
        in Safe Browsing
      * CVE-2024-7005: Insufficient validation of untrusted input
        in Safe Browsing
      * CVE-2024-6990: Uninitialized Use in Dawn
      * CVE-2024-7255: Out of bounds read in WebTransport
      * CVE-2024-7256: Insufficient data validation in Dawn

    gh:

    - Update to version 0.20240730:
      * Rust: link_output, depend_output and runtime_outputs for dylibs
      * Add missing reference section to function_toolchain.cc
      * Do not cleanup args.gn imports located in the output directory.
      * Fix expectations in NinjaRustBinaryTargetWriterTest.SwiftModule
      * Do not add native dependencies to the library search path
      * Support linking frameworks and swiftmodules in Rust targets
      * [desc] Silence print() statements when outputing json
      * infra: Move CI/try builds to Ubuntu-22.04
      * [MinGW] Fix mingw building issues
      * [gn] Fix 'link' in the //examples/simple_build/build/toolchain/BUILD.gn
      * [template] Fix 'rule alink_thin' in the //build/build_linux.ninja.template
      * Allow multiple --ide switches
      * [src] Add '#include <limits>' in the //src/base/files/file_enumerator_win.cc
      * Get updates to infra/recipes.py from upstream
      * Revert 'Teach gn to handle systems with > 64 processors'
      * [apple] Rename the code-signing properties of create_bundle
      * Fix a typo in 'gn help refs' output
      * Revert '[bundle] Use 'phony' builtin tool for create_bundle targets'
      * [bundle] Use 'phony' builtin tool for create_bundle targets
      * [ios] Simplify handling of assets catalog
      * [swift] List all outputs as deps of 'source_set' stamp file
      * [swift] Update `gn check ...` to consider the generated header
      * [swift] Set `restat = 1` to swift build rules
      * Fix build with gcc12
      * [label_matches] Add new functions label_matches(), filter_labels_include() and filter_labels_exclude()
      * [swift] Remove problematic use of 'stamp' tool
      * Implement new --ninja-outputs-file option.
      * Add NinjaOutputsWriter class
      * Move InvokePython() function to its own source file.
      * zos: build with -DZOSLIB_OVERRIDE_CLIB to override creat
      * Enable C++ runtime assertions in debug mode.
      * Fix regression in MakeRelativePath()
      * fix: Fix Windows MakeRelativePath.
      * Add long path support for windows
      * Ensure read_file() files are considered by 'gn analyze'
      * apply 2to3 to for some Python scripts
      * Add rustflags to desc and help output
      * strings: support case insensitive check only in StartsWith/EndsWith
      * add .git-blame-ignore-revs
      * use std::{string,string_view}::{starts_with,ends_with}
      * apply clang-format to all C++ sources
      * add forward declaration in rust_values.h
      * Add `root_patterns` list to build configuration.
      * Use c++20 in GN build
      * update windows sdk to 2024-01-11
      * update windows sdk
      * Add linux-riscv64.
      * Update OWNERS list.
      * remove unused function
      * Ignore build warning -Werror=redundant-move
      * Fix --as=buildfile `gn desc deps` output.
      * Update recipe engine to 9dea1246.
      * treewide: Fix spelling mistakes

    Added rust-bindgen:

    - Version 0.69.1

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228942");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KC4DDO3O7C7P2VVA7A7WIO5RVISNZ3HV/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f1aa27c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7550");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver, chromium, gn and / or rust-bindgen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7550");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-bindgen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.5|SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5 / 15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-127.0.6533.119-bp156.2.14.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-127.0.6533.119-bp156.2.14.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-127.0.6533.119-bp156.2.14.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-127.0.6533.119-bp156.2.14.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-127.0.6533.119-bp156.2.14.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-127.0.6533.119-bp156.2.14.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-127.0.6533.119-bp156.2.14.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-127.0.6533.119-bp156.2.14.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gn-0.20240730-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gn-0.20240730-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bindgen-0.69.1-bp156.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bindgen-0.69.1-bp156.2.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium / gn / rust-bindgen');
}
