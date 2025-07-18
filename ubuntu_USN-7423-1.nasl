#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7423-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233981);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id(
    "CVE-2025-1153",
    "CVE-2025-1176",
    "CVE-2025-1178",
    "CVE-2025-1181",
    "CVE-2025-1182"
  );
  script_xref(name:"IAVA", value:"2025-A-0095");
  script_xref(name:"USN", value:"7423-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : GNU binutils vulnerabilities (USN-7423-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7423-1 advisory.

    It was discovered that GNU binutils incorrectly handled certain inputs. An attacker could possibly use
    this issue to cause a crash, expose sensitive information or execute arbitrary code. (CVE-2025-1153,
    CVE-2025-1182)

    It was discovered that ld in GNU binutils incorrectly handled certain files. An attacker could possibly
    use this issue to execute arbitrary code. (CVE-2025-1176)

    It was discovered that ld in GNU binutils incorrectly handled certain files. An attacker could possibly
    use this issue to cause a crash, expose sensitive information or execute arbitrary code. This issue only
    affected Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 24.10. (CVE-2025-1178, CVE-2025-1181)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7423-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1182");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1176");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-1178");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arc-linux-gnu");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-loongarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-riscv64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-kfreebsd-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnux32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbinutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libctf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgprofng0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsframe1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'binutils', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-common', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-dev', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-source', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'libbinutils', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'libctf-nobfd0', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'libctf0', 'pkgver': '2.34-6ubuntu1.11'},
    {'osver': '22.04', 'pkgname': 'binutils', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-common', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-dev', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-source', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'libbinutils', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'libctf-nobfd0', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '22.04', 'pkgname': 'libctf0', 'pkgver': '2.38-4ubuntu2.8'},
    {'osver': '24.04', 'pkgname': 'binutils', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-arc-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-common', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-dev', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-loongarch64-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-source', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-x86-64-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'libbinutils', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'libctf-nobfd0', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'libctf0', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'libgprofng0', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.04', 'pkgname': 'libsframe1', 'pkgver': '2.42-4ubuntu2.5'},
    {'osver': '24.10', 'pkgname': 'binutils', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-arc-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-common', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-dev', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-for-build', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-for-host', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-loongarch64-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-multiarch', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-source', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-x86-64-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'libbinutils', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'libctf-nobfd0', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'libctf0', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'libgprofng0', 'pkgver': '2.43.1-4ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'libsframe1', 'pkgver': '2.43.1-4ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
