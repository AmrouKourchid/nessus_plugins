#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6727-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193171);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-4421", "CVE-2023-5388", "CVE-2023-6135");
  script_xref(name:"USN", value:"6727-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 : NSS vulnerabilities (USN-6727-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6727-1 advisory.

    It was discovered that NSS incorrectly handled padding when checking PKCS#1 certificates. A remote
    attacker could possibly use this issue to perform Bleichenbacher-like attacks and recover private data.
    This issue only affected Ubuntu 20.04 LTS. (CVE-2023-4421)

    It was discovered that NSS had a timing side-channel when performing RSA decryption. A remote attacker
    could possibly use this issue to recover private data. (CVE-2023-5388)

    It was discovered that NSS had a timing side-channel when using certain NIST curves. A remote attacker
    could possibly use this issue to recover private data. (CVE-2023-6135)

    The NSS package contained outdated CA certificates. This update refreshes the NSS package to version 3.98
    which includes the latest CA certificate bundle and other security improvements.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6727-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libnss3, libnss3-dev and / or libnss3-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libnss3', 'pkgver': '2:3.98-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.98-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.98-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libnss3', 'pkgver': '2:3.98-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.98-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.98-0ubuntu0.22.04.1'},
    {'osver': '23.10', 'pkgname': 'libnss3', 'pkgver': '2:3.98-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.98-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.98-0ubuntu0.23.10.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss3 / libnss3-dev / libnss3-tools');
}
