#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-6f07616b52
#

include('compat.inc');

if (description)
{
  script_id(216232);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id("CVE-2025-0977");
  script_xref(name:"FEDORA", value:"2025-6f07616b52");

  script_name(english:"Fedora 40 : clevis-pin-tpm2 / envision / fido-device-onboard / gotify-desktop / etc (2025-6f07616b52)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2025-6f07616b52 advisory.

    Update the openssl crate to version 0.10.70 and the openssl-sys crate to version 0.9.105.

    This includes a fix for [RUSTSEC-2025-0004](https://rustsec.org/advisories/RUSTSEC-2025-0004.html) /
    CVE-2025-0977 and rebuilds of all packages that statically link the openssl crate.


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6f07616b52");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0977");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clevis-pin-tpm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:envision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fido-device-onboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gotify-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:keylime-agent-rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:keyring-ima-signer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkrun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-afterburn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-vendor-filterer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-coreos-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-eif_build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gst-plugin-reqwest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-nu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-openssl-sys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpm-sequoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-keyring-linter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-octopus-librnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-policy-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sqv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sevctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-snphost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tealdeer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rustup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:s390utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'clevis-pin-tpm2-0.5.3-9.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'envision-2.0.0-4.20241209git2.0.0.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fido-device-onboard-0.5.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gotify-desktop-1.3.7-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'keylime-agent-rust-0.2.7-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'keyring-ima-signer-0.1.0-17.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkrun-1.10.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-afterburn-5.7.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-vendor-filterer-0.5.17-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-coreos-installer-0.23.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-eif_build-0.2.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gst-plugin-reqwest-0.13.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-nu-0.99.1-7.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-openssl-0.10.70-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-openssl-sys-0.9.105-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pore-0.1.17-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpm-sequoia-1.7.0-5.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-keyring-linter-1.0.1-10.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-octopus-librnp-1.10.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-policy-config-0.7.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sqv-1.2.1-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sevctl-0.6.0-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-snphost-0.5.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tealdeer-1.7.1-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustup-1.27.1-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'s390utils-2.33.1-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clevis-pin-tpm2 / envision / fido-device-onboard / gotify-desktop / etc');
}
