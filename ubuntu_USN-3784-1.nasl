#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3784-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117934);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");
  script_xref(name:"USN", value:"3784-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : AppArmor update (USN-3784-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-3784-1 advisory.

    As a security improvement, this update adjusts the private-files abstraction to disallow writing to
    thumbnailer configuration files. Additionally adjust the private-files, private-files-strict and user-
    files abstractions to disallow writes on parent directories of sensitive files.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3784-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-easyprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dh-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libapparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libapparmor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'apparmor-easyprof', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'apparmor-notify', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'apparmor-profiles', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'apparmor-utils', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'dh-apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'libapparmor-dev', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'libapparmor-perl', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'libapparmor1', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'libpam-apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'python-apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'python-libapparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'python3-apparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '14.04', 'pkgname': 'python3-libapparmor', 'pkgver': '2.10.95-0ubuntu2.6~14.04.4'},
    {'osver': '16.04', 'pkgname': 'apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'apparmor-easyprof', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'apparmor-notify', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'apparmor-profiles', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'apparmor-utils', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'dh-apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libapache2-mod-apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libapparmor-dev', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libapparmor-perl', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libapparmor1', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libpam-apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'python-apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'python-libapparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'python3-apparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'python3-libapparmor', 'pkgver': '2.10.95-0ubuntu2.10'},
    {'osver': '18.04', 'pkgname': 'apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'apparmor-easyprof', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'apparmor-notify', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'apparmor-profiles', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'apparmor-utils', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'dh-apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'libapache2-mod-apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'libapparmor-dev', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'libapparmor-perl', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'libapparmor1', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'libpam-apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'python-apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'python-libapparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'python3-apparmor', 'pkgver': '2.12-4ubuntu5.1'},
    {'osver': '18.04', 'pkgname': 'python3-libapparmor', 'pkgver': '2.12-4ubuntu5.1'}
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apparmor / apparmor-easyprof / apparmor-notify / apparmor-profiles / etc');
}
