#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3873-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121506);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2018-17204", "CVE-2018-17205", "CVE-2018-17206");
  script_xref(name:"USN", value:"3873-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Open vSwitch vulnerabilities (USN-3873-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3873-1 advisory.

    It was discovered that Open vSwitch incorrectly decoded certain packets. A remote attacker could possibly
    use this issue to cause Open vSwitch to crash, resulting in a denial of service. (CVE-2018-17204)

    It was discovered that Open vSwitch incorrectly handled processing certain flows. A remote attacker could
    possibly use this issue to cause Open vSwitch to crash, resulting in a denial of service. This issue only
    affected Ubuntu 18.04 LTS. (CVE-2018-17205)

    It was discovered that Open vSwitch incorrectly handled BUNDLE action decoding. A remote attacker could
    possibly use this issue to cause Open vSwitch to crash, resulting in a denial of service. (CVE-2018-17206)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3873-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-switch-dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-testcontroller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-controller-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '16.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-ipsec', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-central', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-common', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-host', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'python-openvswitch', 'pkgver': '2.5.5-0ubuntu0.16.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'ovn-central', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'ovn-common', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'ovn-controller-vtep', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'ovn-host', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'python-openvswitch', 'pkgver': '2.9.2-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.9.2-0ubuntu0.18.04.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch-common / openvswitch-ipsec / openvswitch-pki / etc');
}
