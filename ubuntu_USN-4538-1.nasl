#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4538-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2020-16121", "CVE-2020-16122");
  script_xref(name:"USN", value:"4538-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : PackageKit vulnerabilities (USN-4538-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4538-1 advisory.

    Vaisha Bernard discovered that PackageKit incorrectly handled certain methods. A local attacker could use
    this issue to learn the MIME type of any file on the system. (CVE-2020-16121)

    Sami Niemimki discovered that PackageKit incorrectly handled local deb packages. A local user could
    possibly use this issue to install untrusted packages, contrary to expectations. (CVE-2020-16122)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4538-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-packagekitglib-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-glib2-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-glib2-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpackagekit-glib2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-backend-aptcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-backend-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:packagekit-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-packagekit");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'gir1.2-packagekitglib-1.0', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-packagekit', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'libpackagekit-glib2-16', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'libpackagekit-glib2-dev', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'packagekit', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'packagekit-backend-aptcc', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'packagekit-backend-smart', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'packagekit-gtk3-module', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'packagekit-tools', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '16.04', 'pkgname': 'python3-packagekit', 'pkgver': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'gir1.2-packagekitglib-1.0', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'gstreamer1.0-packagekit', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpackagekit-glib2-18', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libpackagekit-glib2-dev', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'packagekit', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'packagekit-command-not-found', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'packagekit-gtk3-module', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '18.04', 'pkgname': 'packagekit-tools', 'pkgver': '1.1.9-1ubuntu2.18.04.6'},
    {'osver': '20.04', 'pkgname': 'gir1.2-packagekitglib-1.0', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-packagekit', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libpackagekit-glib2-18', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libpackagekit-glib2-dev', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'packagekit', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'packagekit-command-not-found', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'packagekit-gtk3-module', 'pkgver': '1.1.13-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'packagekit-tools', 'pkgver': '1.1.13-2ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-packagekitglib-1.0 / gstreamer1.0-packagekit / etc');
}
