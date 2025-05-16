#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7369-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233299);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id(
    "CVE-2024-25260",
    "CVE-2025-1365",
    "CVE-2025-1371",
    "CVE-2025-1372",
    "CVE-2025-1377"
  );
  script_xref(name:"USN", value:"7369-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS / 24.10 : elfutils vulnerabilities (USN-7369-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7369-1 advisory.

    It was discovered that readelf from elfutils could be made to read out of bounds. If a user or automated
    system were tricked into running readelf on a specially crafted file, an attacker could cause readelf to
    crash, resulting in a denial of service. This issue only affected Ubuntu 24.04 LTS. (CVE-2024-25260)

    It was discovered that readelf from elfutils could be made to write out of bounds. If a user or automated
    system were tricked into running readelf on a specially crafted file, an attacker could cause readelf to
    crash, resulting in a denial of service, or possibly execute arbitrary code. This issue only affected
    Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2025-1365)

    It was discovered that readelf from elfutils could be made to dereference invalid memory. If a user or
    automated system were tricked into running readelf on a specially crafted file, an attacker could cause
    readelf to crash, resulting in a denial of service. This issue only affected Ubuntu 24.04 LTS and Ubuntu
    24.10. (CVE-2025-1371)

    It was discovered that readelf from elfutils could be made to dereference invalid memory. If a user or
    automated system were tricked into running readelf on a specially crafted file, an attacker could cause
    readelf to crash, resulting in a denial of service. (CVE-2025-1372)

    It was discovered that strip from elfutils could be made to dereference invalid memory. If a user or
    automated system were tricked into running strip on a specially crafted file, an attacker could cause
    strip to crash, resulting in a denial of service. (CVE-2025-1377)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7369-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1372");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-1377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:debuginfod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasm1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdebuginfod-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdebuginfod-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdebuginfod1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdebuginfod1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdw1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libelf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libelf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libelf1t64");
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
if (! ('22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'debuginfod', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'elfutils', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libasm-dev', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libasm1', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libdebuginfod-common', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libdebuginfod-dev', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libdebuginfod1', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libdw-dev', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libdw1', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libelf-dev', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libelf1', 'pkgver': '0.186-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'debuginfod', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'elfutils', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libasm-dev', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libasm1t64', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdebuginfod-common', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdebuginfod-dev', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdebuginfod1t64', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdw-dev', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdw1t64', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libelf-dev', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libelf1t64', 'pkgver': '0.190-1.1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'debuginfod', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'elfutils', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libasm-dev', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libasm1t64', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libdebuginfod-common', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libdebuginfod-dev', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libdebuginfod1t64', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libdw-dev', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libdw1t64', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libelf-dev', 'pkgver': '0.191-2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libelf1t64', 'pkgver': '0.191-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'debuginfod / elfutils / libasm-dev / libasm1 / libasm1t64 / etc');
}
