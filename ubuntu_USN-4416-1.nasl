#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4416-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138166);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-12133",
    "CVE-2017-18269",
    "CVE-2018-11236",
    "CVE-2018-11237",
    "CVE-2018-19591",
    "CVE-2018-6485",
    "CVE-2019-19126",
    "CVE-2019-9169",
    "CVE-2020-10029",
    "CVE-2020-1751",
    "CVE-2020-1752"
  );
  script_xref(name:"USN", value:"4416-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : GNU C Library vulnerabilities (USN-4416-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4416-1 advisory.

    Florian Weimer discovered that the GNU C Library incorrectly handled certain memory operations. A remote
    attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2017-12133)

    It was discovered that the GNU C Library incorrectly handled certain SSE2-optimized memmove operations. A
    remote attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of
    service, or possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2017-18269)

    It was discovered that the GNU C Library incorrectly handled certain pathname operations. A remote
    attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-11236)

    It was discovered that the GNU C Library incorrectly handled certain AVX-512-optimized mempcpy operations.
    A remote attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of
    service, or possibly execute arbitrary code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-11237)

    It was discovered that the GNU C Library incorrectly handled certain hostname loookups. A remote attacker
    could use this issue to cause the GNU C Library to crash, resulting in a denial of service, or possibly
    execute arbitrary code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-19591)

    Jakub Wilk discovered that the GNU C Library incorrectly handled certain memalign functions. A remote
    attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2018-6485)

    It was discovered that the GNU C Library incorrectly ignored the LD_PREFER_MAP_32BIT_EXEC environment
    variable after security transitions. A local attacker could use this issue to bypass ASLR restrictions.
    (CVE-2019-19126)

    It was discovered that the GNU C Library incorrectly handled certain regular expressions. A remote
    attacker could possibly use this issue to cause the GNU C Library to crash, resulting in a denial of
    service. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-9169)

    It was discovered that the GNU C Library incorrectly handled certain bit patterns. A remote attacker could
    use this issue to cause the GNU C Library to crash, resulting in a denial of service, or possibly execute
    arbitrary code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2020-10029)

    It was discovered that the GNU C Library incorrectly handled certain signal trampolines on PowerPC. A
    remote attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of
    service, or possibly execute arbitrary code. (CVE-2020-1751)

    It was discovered that the GNU C Library incorrectly handled tilde expansion. A remote attacker could use
    this issue to cause the GNU C Library to crash, resulting in a denial of service, or possibly execute
    arbitrary code. (CVE-2020-1752)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4416-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '16.04', 'pkgname': 'glibc-source', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc-bin', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-armel', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-ppc64', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-i386', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-pic', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-ppc64', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-s390', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-udeb', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'libc6-x32', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'locales', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'locales-all', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'multiarch-support', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '16.04', 'pkgname': 'nscd', 'pkgver': '2.23-0ubuntu11.2'},
    {'osver': '18.04', 'pkgname': 'glibc-source', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc-bin', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-armel', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-i386', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-pic', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-s390', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-udeb', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libc6-x32', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'locales', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'locales-all', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'multiarch-support', 'pkgver': '2.27-3ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'nscd', 'pkgver': '2.27-3ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc6 / libc6-amd64 / etc');
}
