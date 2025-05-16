#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7376-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233471);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-21490");
  script_xref(name:"USN", value:"7376-1");

  script_name(english:"Ubuntu 24.10 : MariaDB vulnerability (USN-7376-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.10 host has packages installed that are affected by a vulnerability as referenced in the USN-7376-1
advisory.

    A security issue was discovered in MariaDB and this update includes a new upstream MariaDB version to fix
    the issue.

    In addition to security fixes, the updated packages contain bug and regression fixes, new features, and
    possibly incompatible changes.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7376-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd19t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-hashicorp-key-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-provider-bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-provider-lz4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-provider-lzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-provider-lzo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-provider-snappy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test-data");
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
if (! ('24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '24.10', 'pkgname': 'libmariadb-dev', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'libmariadb3', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'libmariadbd19t64', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-backup', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-client', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-client-compat', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-client-core', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-common', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-connect-jdbc', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-hashicorp-key-management', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-provider-bzip2', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-provider-lz4', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-provider-lzma', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-provider-lzo', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-provider-snappy', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-s3', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-server', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-server-10.5', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-server-compat', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-server-core', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-test', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'},
    {'osver': '24.10', 'pkgname': 'mariadb-test-data', 'pkgver': '1:11.4.5-0ubuntu0.24.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}
