#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6568-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187682);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");
  script_xref(name:"USN", value:"6568-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : ClamAV update (USN-6568-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by a vulnerability
as referenced in the USN-6568-1 advisory.

    The ClamAV package was updated to a new upstream version to remain compatible with signature database
    downloads.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6568-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav9");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'clamav', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.11+dfsg-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.11+dfsg-0ubuntu0.22.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.11+dfsg-0ubuntu0.23.04.1'},
    {'osver': '23.10', 'pkgname': 'clamav', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamav-base', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamav-daemon', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamav-freshclam', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamav-milter', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamav-testfiles', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'clamdscan', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libclamav-dev', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libclamav11', 'pkgver': '1.0.4+dfsg-0ubuntu0.23.10.1'}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-freshclam / etc');
}
