#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-9790b327cb
#

include('compat.inc');

if (description)
{
  script_id(186602);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");
  script_xref(name:"FEDORA", value:"2023-9790b327cb");

  script_name(english:"Fedora 39 : clevis-pin-tpm2 / keyring-ima-signer / rust-bodhi-cli / etc (2023-9790b327cb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2023-9790b327cb advisory.

    Affected applications were rebuilt against version 0.10.60 of the the `openssl` crate (the Rust bindings
    for OpenSSL) to address two security advisories:

    - https://rustsec.org/advisories/RUSTSEC-2023-0044.html
    - https://rustsec.org/advisories/RUSTSEC-2023-0072.html

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9790b327cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clevis-pin-tpm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:keyring-ima-signer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bodhi-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-coreos-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-fedora-update-feedback");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gst-plugin-reqwest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpm-sequoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-octopus-librnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-policy-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-wot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sevctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-snphost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tealdeer");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'clevis-pin-tpm2-0.5.3-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'keyring-ima-signer-0.1.0-11.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-bodhi-cli-2.1.1-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-coreos-installer-0.18.0-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-fedora-update-feedback-2.1.3-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gst-plugin-reqwest-0.11.1-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pore-0.1.8-5.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpm-sequoia-1.5.0-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-octopus-librnp-1.5.0-4.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-policy-config-0.6.0-6.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sq-0.26.0-10.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-wot-0.5.0-4.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sevctl-0.4.3-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-snphost-0.1.2-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tealdeer-1.6.1-5.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clevis-pin-tpm2 / keyring-ima-signer / rust-bodhi-cli / etc');
}
