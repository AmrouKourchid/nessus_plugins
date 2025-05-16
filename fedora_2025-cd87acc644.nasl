#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-cd87acc644
#

include('compat.inc');

if (description)
{
  script_id(234697);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");
  script_xref(name:"FEDORA", value:"2025-cd87acc644");

  script_name(english:"Fedora 41 : python-pydantic-core / rust-adblock / rust-cookie_store / etc (2025-cd87acc644)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2025-cd87acc644 advisory.

    Update uv to 0.6.14, with [various bugfixes and new features](https://github.com/astral-
    sh/uv/blob/0.6.14/CHANGELOG.md).

    Update rust-idna to 1.0.3 (fixing
    [RUSTSEC-2024-0421](https://rustsec.org/advisories/RUSTSEC-2024-0421.html)), rust-url to 2.5.4, rust-
    adblock to 0.9.6, and rust-cookie_store to 0.21.1; adjust some reverse dependencies of rust-idna. Initial
    packages for many dependencies.

    Update rust-ron to 0.9.

    Update rust-zip to 2.6.1, fixing [GHSA-94vh-gphv-8pm8](https://github.com/zip-
    rs/zip2/security/advisories/GHSA-94vh-gphv-8pm8).

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-cd87acc644");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-pydantic-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-adblock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cookie_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gitui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_locid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_locid_transform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_locid_transform_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_normalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_normalizer_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_properties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_properties_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-icu_provider_macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-idna_adapter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-litemap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-ron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-openpgp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-openpgp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tinystr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-utf16_iter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-version-ranges");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-write16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-writeable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-zerovec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:uv");
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
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'python-pydantic-core-2.27.2-5.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-adblock-0.9.6-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cookie_store-0.21.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gitui-0.26.3-6.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gstreamer-0.23.5-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_collections-1.5.0-3.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_locid-1.5.0-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_locid_transform-1.5.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_locid_transform_data-1.5.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_normalizer-1.5.0-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_normalizer_data-1.5.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_properties-1.5.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_properties_data-1.5.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_provider-1.5.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-icu_provider_macros-1.5.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-idna-1.0.3-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-idna_adapter-1.2.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-litemap-0.7.3-5.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-ron-0.9.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-openpgp-2.0.0-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-openpgp1-1.22.0-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tinystr-0.7.6-4.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-url-2.5.4-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-utf16_iter-1.0.5-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-version-ranges-0.1.1-2.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-write16-1.0.0-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-writeable-0.5.5-3.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-zerovec-0.10.4-4.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-zip-2.6.1-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uv-0.6.14-3.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-pydantic-core / rust-adblock / rust-cookie_store / etc');
}
