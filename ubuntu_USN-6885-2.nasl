#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6885-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202231);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");
  script_xref(name:"USN", value:"6885-2");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS : Apache HTTP Server regression (USN-6885-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-6885-2 advisory.

    USN-6885-1 fixed vulnerabilities in Apache HTTP Server. One of the security fixes introduced a regression
    when proxying requests to a HTTP/2 server. This update fixes the problem.

    We apologize for the inconvenience.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6885-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-uwsgi");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'apache2', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.41-4ubuntu3.20'},
    {'osver': '22.04', 'pkgname': 'apache2', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.52-1ubuntu4.11'},
    {'osver': '24.04', 'pkgname': 'apache2', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.58-1ubuntu8.3'},
    {'osver': '24.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.58-1ubuntu8.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / etc');
}
