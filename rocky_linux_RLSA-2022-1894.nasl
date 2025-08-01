#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:1894.
##

include('compat.inc');

if (description)
{
  script_id(184898);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2022-21658");
  script_xref(name:"RLSA", value:"2022:1894");

  script_name(english:"Rocky Linux 8 : rust-toolset:rhel8 (RLSA-2022:1894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:1894 advisory.

  - Rust is a multi-paradigm, general-purpose programming language designed for performance and safety,
    especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all`
    standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker
    could use this security issue to trick a privileged program into deleting files and directories the
    attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this
    vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs
    to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before
    version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible,
    especially people developing programs expected to run in privileged contexts (including system daemons and
    setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in
    your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be
    vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended
    outside of race conditions. (CVE-2022-21658)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:1894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041504");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21658");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clippy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-std-static-wasm32-unknown-unknown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-std-static-wasm32-wasi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rustfmt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'cargo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-doc-1.58.1-1.module+el8.6.0+826+60f85975', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugger-common-1.58.1-1.module+el8.6.0+826+60f85975', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gdb-1.58.1-1.module+el8.6.0+826+60f85975', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lldb-1.58.1-1.module+el8.6.0+826+60f85975', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-src-1.58.1-1.module+el8.6.0+826+60f85975', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.58.1-1.module+el8.6.0+826+60f85975', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo / cargo-debuginfo / cargo-doc / clippy / clippy-debuginfo / etc');
}
