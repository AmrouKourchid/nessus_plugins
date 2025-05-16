#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3558-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(106620);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2017-15908", "CVE-2018-1049");
  script_xref(name:"USN", value:"3558-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : systemd vulnerabilities (USN-3558-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3558-1 advisory.

    Karim Hossen & Thomas Imbert and Nelson William Gamazo Sanchez independently discovered that systemd-
    resolved incorrectly handled certain DNS responses. A remote attacker could possibly use this issue to
    cause systemd to temporarily stop responding, resulting in a denial of service. This issue only affected
    Ubuntu 16.04 LTS. (CVE-2017-15908)

    It was discovered that systemd incorrectly handled automounted volumes. A local attacker could possibly
    use this issue to cause applications to hang, resulting in a denial of service. (CVE-2018-1049)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3558-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15908");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gudev-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-systemd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'gir1.2-gudev-1.0', 'pkgver': '1:204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libgudev-1.0-0', 'pkgver': '1:204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libgudev-1.0-dev', 'pkgver': '1:204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libpam-systemd', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-daemon-dev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-daemon0', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-id128-0', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-id128-dev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-journal-dev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-journal0', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-login-dev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libsystemd-login0', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libudev-dev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libudev1', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'libudev1-udeb', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'python-systemd', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'systemd', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'systemd-services', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'udev', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '14.04', 'pkgname': 'udev-udeb', 'pkgver': '204-5ubuntu20.26'},
    {'osver': '16.04', 'pkgname': 'libnss-myhostname', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libnss-mymachines', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libnss-resolve', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libpam-systemd', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libsystemd-dev', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libsystemd0', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libudev-dev', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libudev1', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'libudev1-udeb', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'systemd', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'systemd-container', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'systemd-coredump', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'systemd-sysv', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'udev', 'pkgver': '229-4ubuntu21.1'},
    {'osver': '16.04', 'pkgname': 'udev-udeb', 'pkgver': '229-4ubuntu21.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gudev-1.0 / libgudev-1.0-0 / libgudev-1.0-dev / etc');
}
