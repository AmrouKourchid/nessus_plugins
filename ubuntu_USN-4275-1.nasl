#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4275-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133647);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-19872",
    "CVE-2019-18281",
    "CVE-2020-0569",
    "CVE-2020-0570"
  );
  script_xref(name:"USN", value:"4275-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Qt vulnerabilities (USN-4275-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4275-1 advisory.

    It was discovered that Qt incorrectly handled certain PPM images. If a user or automated system were
    tricked into opening a specially crafted PPM file, a remote attacker could cause Qt to crash, resulting in
    a denial of service. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-19872)

    It was discovered that Qt incorrectly handled certain text files. If a user or automated system were
    tricked into opening a specially crafted text file, a remote attacker could cause Qt to crash, resulting
    in a denial of service. This issue only affected Ubuntu 19.10. (CVE-2019-18281)

    It was discovered that Qt incorrectly searched for plugins in the current working directory. An attacker
    could possibly use this issue to execute arbitrary code. (CVE-2020-0569)

    It was discovered that Qt incorrectly searched for libraries relative to the current working directory. An
    attacker could possibly use this issue to execute arbitrary code. This issue only affected Ubuntu 19.10.
    (CVE-2020-0570)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4275-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0570");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5dbus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5libqgtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5printsupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-ibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-gtk-platformtheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-private-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5concurrent5");
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
    {'osver': '16.04', 'pkgname': 'libqt5concurrent5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5core5a', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5dbus5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5gui5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5libqgtk2', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5network5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5opengl5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5opengl5-dev', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5printsupport5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5-mysql', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5-odbc', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5-psql', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5-sqlite', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5sql5-tds', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5test5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5widgets5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'libqt5xml5', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qt5-default', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qt5-qmake', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qt5-qmake-arm-linux-gnueabihf', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qtbase5-dev', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qtbase5-dev-tools', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qtbase5-examples', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '16.04', 'pkgname': 'qtbase5-private-dev', 'pkgver': '5.5.1+dfsg-16ubuntu7.7'},
    {'osver': '18.04', 'pkgname': 'libqt5concurrent5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5core5a', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5dbus5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5gui5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5network5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5opengl5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5opengl5-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5printsupport5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-ibase', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-mysql', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-odbc', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-psql', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-sqlite', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-tds', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5test5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5widgets5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libqt5xml5', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qt5-default', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qt5-gtk-platformtheme', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qt5-qmake', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qt5-qmake-bin', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qtbase5-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qtbase5-dev-tools', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qtbase5-examples', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'qtbase5-private-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt5concurrent5 / libqt5core5a / libqt5dbus5 / libqt5gui5 / etc');
}
