#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4269-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133523);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2018-16888",
    "CVE-2019-20386",
    "CVE-2019-3843",
    "CVE-2019-3844",
    "CVE-2020-1712"
  );
  script_xref(name:"USN", value:"4269-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : systemd vulnerabilities (USN-4269-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4269-1 advisory.

    It was discovered that systemd incorrectly handled certain PIDFile files. A local attacker could possibly
    use this issue to trick systemd into killing privileged processes. This issue only affected Ubuntu 16.04
    LTS. (CVE-2018-16888)

    It was discovered that systemd incorrectly handled certain udevadm trigger commands. A local attacker
    could possibly use this issue to cause systemd to consume resources, leading to a denial of service.
    (CVE-2019-20386)

    Jann Horn discovered that systemd incorrectly handled services that use the DynamicUser property. A local
    attacker could possibly use this issue to access resources owned by a different service in the future.
    This issue only affected Ubuntu 18.04 LTS. (CVE-2019-3843, CVE-2019-3844)

    Tavis Ormandy discovered that systemd incorrectly handled certain Polkit queries. A local attacker could
    use this issue to cause systemd to crash, resulting in a denial of service, or possibly execute arbitrary
    code and escalate privileges. (CVE-2020-1712)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4269-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1712");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1-udeb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libnss-myhostname', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libnss-mymachines', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libnss-resolve', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libpam-systemd', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libsystemd-dev', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libsystemd0', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libudev-dev', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libudev1', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'libudev1-udeb', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'systemd', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'systemd-container', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'systemd-coredump', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'systemd-sysv', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'udev', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '16.04', 'pkgname': 'udev-udeb', 'pkgver': '229-4ubuntu21.27'},
    {'osver': '18.04', 'pkgname': 'libnss-myhostname', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libnss-mymachines', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libnss-resolve', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libnss-systemd', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libpam-systemd', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libsystemd-dev', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libsystemd0', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libudev-dev', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libudev1', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'libudev1-udeb', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd-container', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd-coredump', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd-sysv', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'systemd-tests', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'udev', 'pkgver': '237-3ubuntu10.38'},
    {'osver': '18.04', 'pkgname': 'udev-udeb', 'pkgver': '237-3ubuntu10.38'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-myhostname / libnss-mymachines / libnss-resolve / etc');
}
