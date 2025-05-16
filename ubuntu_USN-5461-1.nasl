##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5461-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161908);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2022-24882", "CVE-2022-24883");
  script_xref(name:"USN", value:"5461-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : FreeRDP vulnerabilities (USN-5461-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5461-1 advisory.

    It was discovered that FreeRDP incorrectly handled empty password values. A remote attacker could use this
    issue to bypass server authentication. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
    Ubuntu 21.10. (CVE-2022-24882)

    It was discovered that FreeRDP incorrectly handled server configurations with an invalid SAM file path. A
    remote attacker could use this issue to bypass server authentication. (CVE-2022-24883)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5461-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24883");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winpr-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'freerdp2-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'freerdp2-shadow-x11', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'freerdp2-wayland', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'freerdp2-x11', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-client2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-server2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-shadow-subsystem2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-shadow2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libfreerdp2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libuwac0-0', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libuwac0-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libwinpr-tools2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libwinpr2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libwinpr2-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'winpr-utils', 'pkgver': '2.2.0+dfsg1-0ubuntu0.18.04.3'},
    {'osver': '20.04', 'pkgname': 'freerdp2-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'freerdp2-shadow-x11', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'freerdp2-wayland', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'freerdp2-x11', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libfreerdp-client2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libfreerdp-server2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libfreerdp-shadow-subsystem2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libfreerdp-shadow2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libfreerdp2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libuwac0-0', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libuwac0-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libwinpr-tools2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libwinpr2-2', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libwinpr2-dev', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'winpr-utils', 'pkgver': '2.2.0+dfsg1-0ubuntu0.20.04.3'},
    {'osver': '22.04', 'pkgname': 'freerdp2-dev', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'freerdp2-shadow-x11', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'freerdp2-wayland', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'freerdp2-x11', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libfreerdp-client2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libfreerdp-server2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libfreerdp-shadow-subsystem2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libfreerdp-shadow2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libfreerdp2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libuwac0-0', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libuwac0-dev', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libwinpr-tools2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libwinpr2-2', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libwinpr2-dev', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'winpr-utils', 'pkgver': '2.6.1+dfsg1-3ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / etc');
}
