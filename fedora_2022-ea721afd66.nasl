#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-ea721afd66
#

include('compat.inc');

if (description)
{
  script_id(211025);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2022-21658");
  script_xref(name:"FEDORA", value:"2022-ea721afd66");

  script_name(english:"Fedora 36 : rust-afterburn / rust-askalono-cli / rust-below / rust-cargo-c / etc (2022-ea721afd66)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2022-ea721afd66 advisory.

    Update the thread_local crate to version 1.1.4. This includes a fix for
    [RUSTSEC-2022-0006](https://rustsec.org/advisories/RUSTSEC-2022-0006.html) (possible memory corruption
    caused by a data race). All applications that statically link thread_local have been rebuilt for this
    version. Additionally, all rebuilt applications now include the fix for
    [CVE-2022-21658](https://rustsec.org/advisories/CVE-2022-21658.html) (Time-of-check Time-of-use race
    condition in `std::fs::remove_dir_all` from the Rust standard library).

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-ea721afd66");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-afterburn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-askalono-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-below");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-insta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-fd-find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-lsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-oxipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-python-launcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ripgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-skim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-thread_local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tokei");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:zola");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rust-afterburn-5.2.0-3.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-askalono-cli-0.4.4-3.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-below-0.4.1-3.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-c-0.9.2-6.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-insta-1.8.0-3.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-fd-find-8.2.1-5.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lsd-0.20.1-8.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-oxipng-5.0.1-4.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-python-launcher-1.0.0-4.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ripgrep-13.0.0-4.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-skim-0.9.4-8.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-thread_local-1.1.4-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tokei-12.0.4-11.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zola-0.12.2-10.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-afterburn / rust-askalono-cli / rust-below / rust-cargo-c / etc');
}
