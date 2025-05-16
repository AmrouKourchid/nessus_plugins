#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6499-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186084);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2023-5981");
  script_xref(name:"USN", value:"6499-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : GnuTLS vulnerability (USN-6499-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by a vulnerability
as referenced in the USN-6499-1 advisory.

    It was discovered that GnuTLS had a timing side-channel when handling certain RSA-PSK key exchanges. A
    remote attacker could possibly use this issue to recover sensitive information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6499-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnutls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:guile-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls-dane0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls-openssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls28-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutlsxx30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gnutls-bin', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'guile-gnutls', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libgnutls-dane0', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libgnutls-openssl27', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libgnutls28-dev', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libgnutls30', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libgnutlsxx28', 'pkgver': '3.6.13-2ubuntu1.9'},
    {'osver': '22.04', 'pkgname': 'gnutls-bin', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'guile-gnutls', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libgnutls-dane0', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libgnutls-openssl27', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libgnutls28-dev', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libgnutls30', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libgnutlsxx28', 'pkgver': '3.7.3-4ubuntu1.3'},
    {'osver': '23.04', 'pkgname': 'gnutls-bin', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'guile-gnutls', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgnutls-dane0', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgnutls-openssl27', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgnutls28-dev', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgnutls30', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgnutlsxx30', 'pkgver': '3.7.8-5ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'gnutls-bin', 'pkgver': '3.8.1-4ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgnutls-dane0', 'pkgver': '3.8.1-4ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgnutls-openssl27', 'pkgver': '3.8.1-4ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgnutls28-dev', 'pkgver': '3.8.1-4ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgnutls30', 'pkgver': '3.8.1-4ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gnutls-bin / guile-gnutls / libgnutls-dane0 / libgnutls-openssl27 / etc');
}
