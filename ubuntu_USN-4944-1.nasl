#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4944-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149405);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");
  script_xref(name:"USN", value:"4944-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : MariaDB vulnerabilities (USN-4944-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-4944-1 advisory.

    This update fixed multiple vulnerabilities in MariaDB.

    Ubuntu 18.04 LTS has been updated to MariaDB 10.1.48. Ubuntu 20.04 LTS has been updated to MariaDB
    10.3.29. Ubuntu 20.10 has been updated to MariaDB 10.3.29. Ubuntu 21.04 has been updated to MariaDB
    10.5.10.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4944-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test-data");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '18.04', 'pkgname': 'libmariadbclient-dev', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbclient-dev-compat', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbclient18', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbd18', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client-10.1', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client-core-10.1', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-tokudb', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server-10.1', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server-core-10.1', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.1.48-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb-dev', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb3', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbclient-dev', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd19', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-backup', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-10.3', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-core-10.3', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-tokudb', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-10.3', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-core-10.3', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.3.29-0ubuntu0.20.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}
