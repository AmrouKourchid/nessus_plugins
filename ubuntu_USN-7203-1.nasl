#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7203-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214098);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/14");

  script_cve_id(
    "CVE-2018-1046",
    "CVE-2018-10851",
    "CVE-2018-14626",
    "CVE-2018-14644",
    "CVE-2020-17482",
    "CVE-2022-27227"
  );
  script_xref(name:"USN", value:"7203-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS : PowerDNS vulnerabilities (USN-7203-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-7203-1 advisory.

    Wei Hao discovered that PowerDNS Authoritative Server incorrectly handled memory when accessing certain
    files. An attacker could possibly use this issue to achieve arbitrary code execution. (CVE-2018-1046)

    It was discovered that PowerDNS Authoritative Server and PowerDNS Recursor incorrectly handled memory when
    receiving certain remote input. An attacker could possibly use this issue to cause denial of service.
    (CVE-2018-10851)

    Kees Monshouwer discovered that PowerDNS Authoritative Server and PowerDNS Recursor incorrectly handled
    request validation after having cached malformed input. An attacker could possibly use this issue to cause
    denial of service. (CVE-2018-14626)

    Toshifumi Sakaguchi discovered that PowerDNS Recursor incorrectly handled requests after having cached
    malformed input. An attacker could possibly use this issue to cause denial of service. (CVE-2018-14644)

    Nathaniel Ferguson discovered that PowerDNS Authoritative Server incorrectly handled memory when receiving
    certain remote input. An attacker could possibly use this issue to obtain sensitive information.
    (CVE-2020-17482)

    Nicolas Dehaine and Dmitry Shabanov discovered that PowerDNS Authoritative Server and PowerDNS Recursor
    incorrectly handled IXFR requests in certain circumstances. An attacker could possibly use this issue to
    cause denial of service. (CVE-2022-27227)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7203-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1046");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-lmdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-lua2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-opendbx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-pipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-backend-tinydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-ixfrdist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pdns-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'pdns-backend-geoip', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-ldap', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-lua', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-mydns', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-mysql', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-pgsql', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-pipe', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-remote', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-sqlite3', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-backend-tinydns', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-recursor', 'pkgver': '4.0.0~alpha2-2ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-server', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pdns-tools', 'pkgver': '4.0.0~alpha2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-bind', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-geoip', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-ldap', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-lua', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-mydns', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-mysql', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-odbc', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-opendbx', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-pgsql', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-pipe', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-remote', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-sqlite3', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-backend-tinydns', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-recursor', 'pkgver': '4.1.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-server', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pdns-tools', 'pkgver': '4.1.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-bind', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-geoip', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-ldap', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-lua', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-mydns', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-mysql', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-odbc', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-pgsql', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-pipe', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-remote', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-sqlite3', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-backend-tinydns', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-ixfrdist', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-recursor', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-server', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pdns-tools', 'pkgver': '4.2.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-bind', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-geoip', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-ldap', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-lmdb', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-lua2', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-mysql', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-odbc', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-pgsql', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-pipe', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-remote', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-sqlite3', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-backend-tinydns', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-ixfrdist', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-recursor', 'pkgver': '4.6.0-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-server', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pdns-tools', 'pkgver': '4.5.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pdns-backend-bind / pdns-backend-geoip / pdns-backend-ldap / etc');
}
