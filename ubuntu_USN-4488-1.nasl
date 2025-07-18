#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4488-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140267);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2020-14346",
    "CVE-2020-14347",
    "CVE-2020-14361",
    "CVE-2020-14362"
  );
  script_xref(name:"USN", value:"4488-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : X.Org X Server vulnerabilities (USN-4488-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4488-1 advisory.

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled the input extension protocol. A
    local attacker could possibly use this issue to escalate privileges. (CVE-2020-14346)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly initialized memory. A local attacker could
    possibly use this issue to obtain sensitive information. (CVE-2020-14347)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled the XkbSelectEvents function. A
    local attacker could possibly use this issue to escalate privileges. (CVE-2020-14361)

    Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled the XRecordRegisterClients
    function. A local attacker could possibly use this issue to escalate privileges. (CVE-2020-14362)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4488-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-hwe-18.04");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'xdmx', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xmir', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xmir-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xnest', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core-udeb', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xvfb', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xwayland', 'pkgver': '2:1.18.4-0ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'xwayland-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.3'},
    {'osver': '18.04', 'pkgname': 'xdmx', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xmir', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xnest', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xorg-server-source-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '18.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xephyr-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core-udeb', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-dev-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-legacy-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xvfb', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xwayland', 'pkgver': '2:1.19.6-1ubuntu4.5'},
    {'osver': '18.04', 'pkgname': 'xwayland-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.2'},
    {'osver': '20.04', 'pkgname': 'xdmx', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xnest', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-core-udeb', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xvfb', 'pkgver': '2:1.20.8-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xwayland', 'pkgver': '2:1.20.8-2ubuntu2.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xmir / xmir-hwe-16.04 / xnest / etc');
}
