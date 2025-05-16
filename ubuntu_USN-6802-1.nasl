#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6802-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198154);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id("CVE-2024-4317");
  script_xref(name:"USN", value:"6802-1");

  script_name(english:"Ubuntu 22.04 LTS / 23.10 / 24.04 LTS : PostgreSQL vulnerability (USN-6802-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-6802-1 advisory.

    Lukas Fittl discovered that PostgreSQL incorrectly performed authorization in the built-in pg_stats_ext
    and pg_stats_ext_exprs views. An unprivileged database user can use this issue to read most common values
    and other statistics from CREATE STATISTICS commands of other users.

    NOTE: This update will only fix fresh PostgreSQL installations. Current PostgreSQL installations will
    remain vulnerable to this issue until manual steps are performed. Please see the instructions in the
    changelog located at /usr/share/doc/postgresql-*/changelog.Debian.gz after the updated packages have been
    installed, or in the PostgreSQL release notes located here:

    https://www.postgresql.org/docs/16/release-16-3.html https://www.postgresql.org/docs/15/release-15-7.html
    https://www.postgresql.org/docs/14/release-14-12.html

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6802-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4317");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython3-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'libecpg-compat3', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libecpg-dev', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libecpg6', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpgtypes3', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpq-dev', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpq5', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-client-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-plperl-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-plpython3-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-pltcl-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'postgresql-server-dev-14', 'pkgver': '14.12-0ubuntu0.22.04.1'},
    {'osver': '23.10', 'pkgname': 'libecpg-compat3', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libecpg-dev', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libecpg6', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libpgtypes3', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libpq-dev', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'libpq5', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-client-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-plperl-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-plpython3-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-pltcl-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'postgresql-server-dev-15', 'pkgver': '15.7-0ubuntu0.23.10.1'},
    {'osver': '24.04', 'pkgname': 'libecpg-compat3', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libecpg-dev', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libecpg6', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libpgtypes3', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libpq-dev', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libpq5', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-16', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-client-16', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-plperl-16', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-plpython3-16', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-pltcl-16', 'pkgver': '16.3-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'postgresql-server-dev-16', 'pkgver': '16.3-0ubuntu0.24.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg-compat3 / libecpg-dev / libecpg6 / libpgtypes3 / libpq-dev / etc');
}
