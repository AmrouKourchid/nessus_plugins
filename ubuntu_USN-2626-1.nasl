#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2626-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83989);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-0190",
    "CVE-2015-0295",
    "CVE-2015-1858",
    "CVE-2015-1859",
    "CVE-2015-1860"
  );
  script_bugtraq_id(
    67087,
    73029,
    74302,
    74307,
    74309,
    74310
  );
  script_xref(name:"USN", value:"2626-1");

  script_name(english:"Ubuntu 14.04 LTS : Qt vulnerabilities (USN-2626-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2626-1 advisory.

    Wolfgang Schenk discovered that Qt incorrectly handled certain malformed GIF images. If a user or
    automated system were tricked into opening a specially crafted GIF image, a remote attacker could use this
    issue to cause Qt to crash, resulting in a denial of service. This issue only applied to Ubuntu 12.04 LTS
    and Ubuntu 14.04 LTS. (CVE-2014-0190)

    Fabian Vogt discovered that Qt incorrectly handled certain malformed BMP images. If a user or automated
    system were tricked into opening a specially crafted BMP image, a remote attacker could use this issue to
    cause Qt to crash, resulting in a denial of service. (CVE-2015-0295)

    Richard Moore and Fabian Vogt discovered that Qt incorrectly handled certain malformed BMP images. If a
    user or automated system were tricked into opening a specially crafted BMP image, a remote attacker could
    use this issue to cause Qt to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2015-1858)

    Richard Moore and Fabian Vogt discovered that Qt incorrectly handled certain malformed ICO images. If a
    user or automated system were tricked into opening a specially crafted ICO image, a remote attacker could
    use this issue to cause Qt to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2015-1859)

    Richard Moore and Fabian Vogt discovered that Qt incorrectly handled certain malformed GIF images. If a
    user or automated system were tricked into opening a specially crafted GIF image, a remote attacker could
    use this issue to cause Qt to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2015-1860)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2626-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1860");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-1859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5printsupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qdbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-linguist-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qmlviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtcore4-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-folderlistmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-gestures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-particles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-shaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-scripttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5dbus5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libqt4-assistant', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-core', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-dbus', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-declarative', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-declarative-folderlistmodel', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-declarative-gestures', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-declarative-particles', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-declarative-shaders', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-designer', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-dev', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-dev-bin', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-gui', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-help', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-network', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-opengl', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-opengl-dev', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-private-dev', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-qt3support', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-script', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-scripttools', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql-mysql', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql-odbc', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql-psql', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql-sqlite', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-sql-tds', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-svg', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-test', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-webkit', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-xml', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt4-xmlpatterns', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqt5concurrent5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5core5a', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5dbus5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5gui5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5network5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5opengl5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5opengl5-dev', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5printsupport5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5-mysql', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5-odbc', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5-psql', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5-sqlite', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5sql5-tds', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5test5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5widgets5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqt5xml5', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'libqtcore4', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqtdbus4', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'libqtgui4', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qdbus', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-default', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-demos', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-designer', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-dev-tools', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-linguist-tools', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-qmake', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-qmlviewer', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt4-qtconfig', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'},
    {'osver': '14.04', 'pkgname': 'qt5-default', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qt5-qmake', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qtbase5-dev', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qtbase5-dev-tools', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qtbase5-examples', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qtbase5-private-dev', 'pkgver': '5.2.1+dfsg-1ubuntu14.3'},
    {'osver': '14.04', 'pkgname': 'qtcore4-l10n', 'pkgver': '4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt4-assistant / libqt4-core / libqt4-dbus / libqt4-declarative / etc');
}
