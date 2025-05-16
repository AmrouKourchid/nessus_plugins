#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6587-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189087);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-0408",
    "CVE-2024-0409",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );
  script_xref(name:"USN", value:"6587-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : X.Org X Server vulnerabilities (USN-6587-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6587-1 advisory.

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled memory when processing the
    DeviceFocusEvent and ProcXIQueryPointer APIs. An attacker could possibly use this issue to cause the X
    Server to crash, obtain sensitive information, or execute arbitrary code. (CVE-2023-6816)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled reattaching to a different master
    device. An attacker could use this issue to cause the X Server to crash, leading to a denial of service,
    or possibly execute arbitrary code. (CVE-2024-0229)

    Olivier Fourdan and Donn Seeley discovered that the X.Org X Server incorrectly labeled GLX PBuffers when
    used with SELinux. An attacker could use this issue to cause the X Server to crash, leading to a denial of
    service. (CVE-2024-0408)

    Olivier Fourdan discovered that the X.Org X Server incorrectly handled the curser code when used with
    SELinux. An attacker could use this issue to cause the X Server to crash, leading to a denial of service.
    (CVE-2024-0409)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled memory when processing the
    XISendDeviceHierarchyEvent API. An attacker could possibly use this issue to cause the X Server to crash,
    or execute arbitrary code. (CVE-2024-21885)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled devices being disabled. An attacker
    could possibly use this issue to cause the X Server to crash, or execute arbitrary code. (CVE-2024-21886)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6587-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'xdmx', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xnest', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xvfb', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '20.04', 'pkgname': 'xwayland', 'pkgver': '2:1.20.13-1ubuntu1~20.04.14'},
    {'osver': '22.04', 'pkgname': 'xnest', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xserver-common', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xvfb', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.7'},
    {'osver': '22.04', 'pkgname': 'xwayland', 'pkgver': '2:22.1.1-1ubuntu0.10'},
    {'osver': '23.04', 'pkgname': 'xnest', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xserver-common', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xvfb', 'pkgver': '2:21.1.7-1ubuntu3.6'},
    {'osver': '23.04', 'pkgname': 'xwayland', 'pkgver': '2:22.1.8-1ubuntu1.4'},
    {'osver': '23.10', 'pkgname': 'xnest', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xorg-server-source', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xserver-common', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xserver-xephyr', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xvfb', 'pkgver': '2:21.1.7-3ubuntu2.6'},
    {'osver': '23.10', 'pkgname': 'xwayland', 'pkgver': '2:23.2.0-1ubuntu0.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / xserver-common / etc');
}
