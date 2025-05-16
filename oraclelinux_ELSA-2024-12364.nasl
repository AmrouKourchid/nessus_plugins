#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12364.
##

include('compat.inc');

if (description)
{
  script_id(195197);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2024-28834", "CVE-2024-28835");

  script_name(english:"Oracle Linux 9 : gnutls (ELSA-2024-12364)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12364 advisory.

    [3.8.3-4_fips]
    - Add FIPS package change: add fips suffix to Release and
      set Epoch to 10 [Orabug: 35925409]
    - Update FIPS module name for Oracle Linux [Orabug: 35925409]

    [3.8.3-4]
    - Bump release to ensure el9 package is greater than el9_* packages

    [3.8.3-3]
    - Bump release to ensure el9 package is greater than el9_* packages

    [3.8.3-2]
    - Fix timing side-channel in deterministic ECDSA (RHEL-28959)
    - Fix potential crash during chain building/verification (RHEL-28954)

    [3.8.3-1]
    - Update to gnutls 3.8.3 (RHEL-14891)

    [3.8.2-3]
    - Skip KTLS test exercising ChaCha20-Poly1305 in TLS 1.3 as well (RHEL-18498)

    [3.8.2-2]
    - Bump nettle dependency to 3.9.1
    - Skip KTLS test exercising ChaCha20-Poly1305 in TLS 1.2 (RHEL-18498)

    [3.8.2-1]
    - Update to gnutls 3.8.2 (RHEL-14891)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12364.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::u3_security_validation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'gnutls-3.8.3-4.el9_4_fips', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-c++-3.8.3-4.el9_4_fips', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-dane-3.8.3-4.el9_4_fips', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-devel-3.8.3-4.el9_4_fips', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-utils-3.8.3-4.el9_4_fips', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-3.8.3-4.el9_4_fips', 'cpu':'i686', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-c++-3.8.3-4.el9_4_fips', 'cpu':'i686', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-dane-3.8.3-4.el9_4_fips', 'cpu':'i686', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-devel-3.8.3-4.el9_4_fips', 'cpu':'i686', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-utils-3.8.3-4.el9_4_fips', 'cpu':'i686', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-3.8.3-4.el9_4_fips', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-c++-3.8.3-4.el9_4_fips', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-dane-3.8.3-4.el9_4_fips', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-devel-3.8.3-4.el9_4_fips', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'gnutls-utils-3.8.3-4.el9_4_fips', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gnutls / gnutls-c++ / gnutls-dane / etc');
}
