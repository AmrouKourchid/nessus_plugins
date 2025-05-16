#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3038-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(92409);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2016-5387");
  script_xref(name:"USN", value:"3038-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Apache HTTP Server vulnerability (USN-3038-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-3038-1 advisory.

    It was discovered that the Apache HTTP Server would set the HTTP_PROXY environment variable based on the
    contents of the Proxy header from HTTP requests. A remote attacker could possibly use this issue in
    combination with CGI scripts that honour the HTTP_PROXY variable to redirect outgoing HTTP requests.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3038-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-macro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'apache2', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-event', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-itk', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-prefork', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-worker', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'apache2.2-bin', 'pkgver': '2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-macro', 'pkgver': '1:2.4.7-1ubuntu4.13'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-proxy-html', 'pkgver': '1:2.4.7-1ubuntu4.13'},
    {'osver': '16.04', 'pkgname': 'apache2', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.18-2ubuntu3.1'},
    {'osver': '16.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.18-2ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / etc');
}
