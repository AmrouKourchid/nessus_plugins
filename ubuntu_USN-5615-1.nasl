#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5615-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165204);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2020-35525", "CVE-2020-35527");
  script_xref(name:"USN", value:"5615-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : SQLite vulnerabilities (USN-5615-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5615-1 advisory.

    It was discovered that SQLite incorrectly handled INTERSEC query processing. An attacker could use this
    issue to cause SQLite to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2020-35525)

    It was discovered that SQLite incorrectly handled ALTER TABLE for views that have a nested FROM clause.

    An attacker could use this issue to cause SQLite to crash, resulting in a denial of service, or possibly
    execute arbitrary code. This issue was only addressed in Ubuntu 20.04 LTS. (CVE-2020-35527)

    It was discovered that SQLite incorrectly handled embedded null characters when tokenizing certain unicode
    strings. This issue could result in incorrect results. This issue only affected Ubuntu 20.04 LTS.
    (CVE-2021-20223)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5615-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sqlite3");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'lemon', 'pkgver': '3.22.0-1ubuntu0.6'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-0', 'pkgver': '3.22.0-1ubuntu0.6'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-dev', 'pkgver': '3.22.0-1ubuntu0.6'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-tcl', 'pkgver': '3.22.0-1ubuntu0.6'},
    {'osver': '18.04', 'pkgname': 'sqlite3', 'pkgver': '3.22.0-1ubuntu0.6'},
    {'osver': '20.04', 'pkgname': 'lemon', 'pkgver': '3.31.1-4ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-0', 'pkgver': '3.31.1-4ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-dev', 'pkgver': '3.31.1-4ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-tcl', 'pkgver': '3.31.1-4ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'sqlite3', 'pkgver': '3.31.1-4ubuntu0.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / libsqlite3-0 / libsqlite3-dev / libsqlite3-tcl / sqlite3');
}
