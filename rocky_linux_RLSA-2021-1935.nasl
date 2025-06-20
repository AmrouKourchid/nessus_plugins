#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1935.
##

include('compat.inc');

if (description)
{
  script_id(184983);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2020-36317", "CVE-2020-36318");
  script_xref(name:"RLSA", value:"2021:1935");

  script_name(english:"Rocky Linux 8 : rust-toolset:rhel8 (RLSA-2021:1935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:1935 advisory.

  - In the standard library in Rust before 1.49.0, String::retain() function has a panic safety problem. It
    allows creation of a non-UTF-8 Rust string when the provided closure panics. This bug could result in a
    memory safety violation when other string APIs assume that UTF-8 encoding is used on the same string.
    (CVE-2020-36317)

  - In the standard library in Rust before 1.49.0, VecDeque::make_contiguous has a bug that pops the same
    element more than once under certain condition. This bug could result in a use-after-free or double free.
    (CVE-2020-36318)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949192");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36318");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
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
    {'reference':'cargo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-doc-1.49.0-1.module+el8.4.0+416+259a129a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugger-common-1.49.0-1.module+el8.4.0+416+259a129a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gdb-1.49.0-1.module+el8.4.0+416+259a129a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lldb-1.49.0-1.module+el8.4.0+416+259a129a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-src-1.49.0-1.module+el8.4.0+416+259a129a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.49.0-1.module+el8.4.0+416+259a129a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
