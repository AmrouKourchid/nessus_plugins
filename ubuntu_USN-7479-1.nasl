#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7479-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235159);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id(
    "CVE-2025-21574",
    "CVE-2025-21575",
    "CVE-2025-21577",
    "CVE-2025-21579",
    "CVE-2025-21580",
    "CVE-2025-21581",
    "CVE-2025-21584",
    "CVE-2025-21585",
    "CVE-2025-21588",
    "CVE-2025-30681",
    "CVE-2025-30682",
    "CVE-2025-30683",
    "CVE-2025-30684",
    "CVE-2025-30685",
    "CVE-2025-30687",
    "CVE-2025-30688",
    "CVE-2025-30689",
    "CVE-2025-30693",
    "CVE-2025-30695",
    "CVE-2025-30696",
    "CVE-2025-30699",
    "CVE-2025-30703",
    "CVE-2025-30704",
    "CVE-2025-30705",
    "CVE-2025-30715",
    "CVE-2025-30721",
    "CVE-2025-30722"
  );
  script_xref(name:"USN", value:"7479-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 : MySQL vulnerabilities (USN-7479-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-7479-1 advisory.

    Multiple security issues were discovered in MySQL and this update includes new upstream MySQL versions to
    fix these issues.

    MySQL has been updated to 8.0.42 in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu
    24.10. Ubuntu 25.04 has been updated to MySQL 8.4.5.

    In addition to security fixes, the updated packages contain bug fixes, new features, and possibly
    incompatible changes.

    Please see the following for more information:

    https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-42.html
    https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-5.html https://www.oracle.com/security-
    alerts/cpuapr2025.html

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7479-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:25.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release || '25.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10 / 25.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.42-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.42-0ubuntu0.22.04.1'},
    {'osver': '24.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.42-0ubuntu0.24.04.1'},
    {'osver': '24.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.42-0ubuntu0.24.10.1'},
    {'osver': '25.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'libmysqlclient24', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-client', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-client-core', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-router', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-server', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-server-core', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-source', 'pkgver': '8.4.5-0ubuntu0.1'},
    {'osver': '25.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.4.5-0ubuntu0.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient21 / libmysqlclient24 / etc');
}
