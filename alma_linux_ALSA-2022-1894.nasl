##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1894.
##

include('compat.inc');

if (description)
{
  script_id(161156);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2022-21658");
  script_xref(name:"ALSA", value:"2022:1894");

  script_name(english:"AlmaLinux 8 : rust-toolset:rhel8 (ALSA-2022:1894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:1894 advisory.

    * rust: Race condition in remove_dir_all leading to removal of files outside of the directory being
    removed (CVE-2022-21658)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1894.html");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cargo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-std-static-wasm32-unknown-unknown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-std-static-wasm32-wasi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/rust-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module rust-toolset:rhel8');
if ('rhel8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module rust-toolset:' + module_ver);

var appstreams = {
    'rust-toolset:rhel8': [
      {'reference':'cargo-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-doc-1.58.1-1.module_el8.6.0+2748+176088b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-debugger-common-1.58.1-1.module_el8.6.0+2748+176088b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-gdb-1.58.1-1.module_el8.6.0+2748+176088b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-lldb-1.58.1-1.module_el8.6.0+2748+176088b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-src-1.58.1-1.module_el8.6.0+2748+176088b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.58.1-1.module_el8.6.0+2748+176088b3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module rust-toolset:rhel8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo / cargo-doc / clippy / rls / rust / rust-analysis / etc');
}
