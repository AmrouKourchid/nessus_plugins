#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5155-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155687);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2021-3658", "CVE-2021-41229", "CVE-2021-43400");
  script_xref(name:"USN", value:"5155-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : BlueZ vulnerabilities (USN-5155-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5155-1 advisory.

    It was discovered that BlueZ incorrectly handled the Discoverable status when a device is powered down.
    This could result in devices being powered up discoverable, contrary to expectations. This issue only
    affected Ubuntu 20.04 LTS, Ubuntu 21.04, and Ubuntu 21.10. (CVE-2021-3658)

    It was discovered that BlueZ incorrectly handled certain memory operations. A remote attacker could
    possibly use this issue to cause BlueZ to consume resources, leading to a denial of service.
    (CVE-2021-41229)

    It was discovered that the BlueZ gatt server incorrectly handled disconnects. A remote attacker could
    possibly use this issue to cause BlueZ to crash, leading to a denial of service. (CVE-2021-43400)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5155-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43400");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluez-obexd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bluez-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbluetooth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbluetooth3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'bluetooth', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'bluez', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'bluez-cups', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'bluez-hcidump', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'bluez-obexd', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'bluez-tests', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'libbluetooth-dev', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '18.04', 'pkgname': 'libbluetooth3', 'pkgver': '5.48-0ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'bluetooth', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'bluez', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'bluez-cups', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'bluez-hcidump', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'bluez-obexd', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'bluez-tests', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'libbluetooth-dev', 'pkgver': '5.53-0ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'libbluetooth3', 'pkgver': '5.53-0ubuntu3.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bluetooth / bluez / bluez-cups / bluez-hcidump / bluez-obexd / etc');
}
