#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7317-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(218383);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id("CVE-2022-23303", "CVE-2022-23304", "CVE-2022-37660");
  script_xref(name:"USN", value:"7317-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : wpa_supplicant and hostapd vulnerabilities (USN-7317-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7317-1 advisory.

    George Chatzisofroniou and Panayiotis Kotzanikolaou discovered that wpa_supplicant and hostapd reused
    encryption elements in the PKEX protocol. An attacker could possibly use this issue to impersonate a
    wireless access point, and obtain sensitive information. (CVE-2022-37660)

    Daniel De Almeida Braga, Mohamed Sabt, and Pierre-Alain Fouque discovered that wpa_supplicant and hostapd
    were vulnerable to side channel attacks due to the cache access patterns. An attacker could possibly use
    this issue to obtain sensitive information. This issue only affected Ubuntu 20.04 LTS. (CVE-2022-23303,
    CVE-2022-23304)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7317-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eapoltest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpa-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpasupplicant");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'hostapd', 'pkgver': '2:2.9-1ubuntu4.6'},
    {'osver': '20.04', 'pkgname': 'wpagui', 'pkgver': '2:2.9-1ubuntu4.6'},
    {'osver': '20.04', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.9-1ubuntu4.6'},
    {'osver': '22.04', 'pkgname': 'eapoltest', 'pkgver': '2:2.10-6ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'hostapd', 'pkgver': '2:2.10-6ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libwpa-client-dev', 'pkgver': '2:2.10-6ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'wpagui', 'pkgver': '2:2.10-6ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.10-6ubuntu2.2'},
    {'osver': '24.04', 'pkgname': 'eapoltest', 'pkgver': '2:2.10-21ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'hostapd', 'pkgver': '2:2.10-21ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libwpa-client-dev', 'pkgver': '2:2.10-21ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'wpagui', 'pkgver': '2:2.10-21ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.10-21ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'eapoltest', 'pkgver': '2:2.10-22ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'hostapd', 'pkgver': '2:2.10-22ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libwpa-client-dev', 'pkgver': '2:2.10-22ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'wpagui', 'pkgver': '2:2.10-22ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.10-22ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eapoltest / hostapd / libwpa-client-dev / wpagui / wpasupplicant');
}
