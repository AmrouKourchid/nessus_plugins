#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6941-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204954);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/30");

  script_cve_id("CVE-2024-4032");
  script_xref(name:"USN", value:"6941-1");

  script_name(english:"Ubuntu 24.04 LTS : Python vulnerability (USN-6941-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-6941-1 advisory.

    It was discovered that the Python ipaddress module contained incorrect information about which IP address
    ranges were considered private or globally reachable. This could possibly result in
    applications applying incorrect security policies.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6941-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-venv");
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
if (! ('24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '24.04', 'pkgname': 'idle-python3.12', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libpython3.12-dev', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libpython3.12-minimal', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libpython3.12-stdlib', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libpython3.12-testsuite', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libpython3.12t64', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-dev', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-examples', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-full', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-minimal', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-nopie', 'pkgver': '3.12.3-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3.12-venv', 'pkgver': '3.12.3-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.12 / libpython3.12-dev / libpython3.12-minimal / etc');
}
