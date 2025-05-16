#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6272-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179340);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-22006",
    "CVE-2023-22036",
    "CVE-2023-22041",
    "CVE-2023-22044",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-25193"
  );
  script_xref(name:"USN", value:"6272-1");

  script_name(english:"Ubuntu 23.04 : OpenJDK 20 vulnerabilities (USN-6272-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 23.04 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-6272-1 advisory.

    Motoyasu Saburi discovered that OpenJDK 20 incorrectly handled special characters in file name parameters.
    An attacker could possibly use this issue to insert, edit or obtain sensitive information.
    (CVE-2023-22006)

    Eirik Bjrsns discovered that OpenJDK 20 incorrectly handled certain ZIP archives. An attacker could
    possibly use this issue to cause a denial of service. (CVE-2023-22036)

    David Stancu discovered that OpenJDK 20 had a flaw in the AES cipher implementation. An attacker could
    possibly use this issue to obtain sensitive information. (CVE-2023-22041)

    Zhiqiang Zang discovered that OpenJDK 20 incorrectly handled array accesses when using the binary '%'
    operator. An attacker could possibly use this issue to obtain sensitive information. (CVE-2023-22044)

    Zhiqiang Zang discovered that OpenJDK 20 incorrectly handled array accesses. An attacker could possibly
    use this issue to obtain sensitive information. (CVE-2023-22045)

    It was discovered that OpenJDK 20 incorrectly sanitized URIs strings. An attacker could possibly use this
    issue to insert, edit or obtain sensitive information. (CVE-2023-22049)

    It was discovered that OpenJDK 20 incorrectly handled certain glyphs. An attacker could possibly use this
    issue to cause a denial of service. (CVE-2023-25193)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6272-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-source");
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
if (! ('23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '23.04', 'pkgname': 'openjdk-20-demo', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk-headless', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-headless', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-zero', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-source', 'pkgver': '20.0.2+9+ds1-0ubuntu1~23.04'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-20-demo / openjdk-20-jdk / openjdk-20-jdk-headless / etc');
}
