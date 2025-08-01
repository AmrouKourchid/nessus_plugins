#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6381-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181560);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-19724",
    "CVE-2020-19726",
    "CVE-2020-21490",
    "CVE-2020-35342",
    "CVE-2021-46174",
    "CVE-2022-44840",
    "CVE-2022-45703",
    "CVE-2022-47695"
  );
  script_xref(name:"USN", value:"6381-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM : GNU binutils vulnerabilities (USN-6381-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6381-1 advisory.

    It was discovered that a memory leak existed in certain GNU binutils modules. An attacker could possibly
    use this issue to cause a denial of service (memory exhaustion). (CVE-2020-19724, CVE-2020-21490)

    It was discovered that GNU binutils was not properly performing bounds checks in several functions, which
    could lead to a buffer overflow. An attacker could possibly use this issue to cause a denial of service,
    expose sensitive information or execute arbitrary code. (CVE-2020-19726, CVE-2021-46174, CVE-2022-45703)

    It was discovered that GNU binutils was not properly initializing heap memory when processing certain
    print instructions. An attacker could possibly use this issue to expose sensitive information.
    (CVE-2020-35342)

    It was discovered that GNU binutils was not properly handling the logic behind certain memory management
    related operations, which could lead to a buffer overflow. An attacker could possibly use this issue to
    cause a denial of service or execute arbitrary code. (CVE-2022-44840)

    It was discovered that GNU binutils was not properly handling the logic behind certain memory management
    related operations, which could lead to an invalid memory access. An attacker could possibly use this
    issue to cause a denial of service. (CVE-2022-47695)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6381-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-19726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-for-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-for-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-kfreebsd-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsel-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa32r6-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa32r6el-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6el-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-riscv64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-kfreebsd-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnux32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbinutils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'binutils', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-source', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm7', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-common', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-dev', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mips64-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mips64el-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa32r6-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa32r6el-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6el-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6el-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-source', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libbinutils', 'pkgver': '2.30-21ubuntu1~18.04.9+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
