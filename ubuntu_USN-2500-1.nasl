#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2500-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81398);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2013-6424", "CVE-2015-0255");
  script_bugtraq_id(64127, 72578);
  script_xref(name:"USN", value:"2500-1");

  script_name(english:"Ubuntu 14.04 LTS : X.Org X server vulnerabilities (USN-2500-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2500-1 advisory.

    Olivier Fourdan discovered that the X.Org X server incorrectly handled XkbSetGeometry requests resulting
    in an information leak. An attacker able to connect to an X server, either locally or remotely, could use
    this issue to possibly obtain sensitive information. (CVE-2015-0255)

    It was discovered that the X.Org X server incorrectly handled certain trapezoids. An attacker able to
    connect to an X server, either locally or remotely, could use this issue to possibly crash the server.
    This issue only affected Ubuntu 12.04 LTS. (CVE-2013-6424)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2500-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0255");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-6424");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-lts-utopic");
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
    {'osver': '14.04', 'pkgname': 'xdmx', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xnest', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xorg-server-source-lts-utopic', 'pkgver': '2:1.16.0-1ubuntu1.2~trusty2'},
    {'osver': '14.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xserver-xephyr-lts-utopic', 'pkgver': '2:1.16.0-1ubuntu1.2~trusty2'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-core-lts-utopic', 'pkgver': '2:1.16.0-1ubuntu1.2~trusty2'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-core-udeb', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-dev-lts-utopic', 'pkgver': '2:1.16.0-1ubuntu1.2~trusty2'},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xvfb', 'pkgver': '2:1.15.1-0ubuntu2.7'},
    {'osver': '14.04', 'pkgname': 'xwayland-lts-utopic', 'pkgver': '2:1.16.0-1ubuntu1.2~trusty2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / etc');
}
