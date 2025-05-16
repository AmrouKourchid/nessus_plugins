#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2496-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81255);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2012-3509",
    "CVE-2014-8484",
    "CVE-2014-8485",
    "CVE-2014-8501",
    "CVE-2014-8502",
    "CVE-2014-8503",
    "CVE-2014-8504",
    "CVE-2014-8737",
    "CVE-2014-8738"
  );
  script_bugtraq_id(
    55281,
    70714,
    70741,
    70761,
    70866,
    70868,
    70869,
    70908,
    71083
  );
  script_xref(name:"USN", value:"2496-1");

  script_name(english:"Ubuntu 14.04 LTS : GNU binutils vulnerabilities (USN-2496-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2496-1 advisory.

    Michal Zalewski discovered that the setup_group function in libbfd in GNU binutils did not properly check
    group headers in ELF files. An attacker could use this to craft input that could cause a denial of service
    (application crash) or possibly execute arbitrary code. (CVE-2014-8485)

    Hanno Bck discovered that the _bfd_XXi_swap_aouthdr_in function in libbfd in GNU binutils allowed out-
    of-bounds writes. An attacker could use this to craft input that could cause a denial of service
    (application crash) or possibly execute arbitrary code. (CVE-2014-8501)

    Hanno Bck discovered a heap-based buffer overflow in the pe_print_edata function in libbfd in GNU
    binutils. An attacker could use this to craft input that could cause a denial of service (application
    crash) or possibly execute arbitrary code. (CVE-2014-8502)

    Alexander Cherepanov discovered multiple directory traversal vulnerabilities in GNU binutils. An attacker
    could use this to craft input that could delete arbitrary files. (CVE-2014-8737)

    Alexander Cherepanov discovered the _bfd_slurp_extended_name_table function in libbfd in GNU binutils
    allowed invalid writes when handling extended name tables in an archive. An attacker could use this to
    craft input that could cause a denial of service (application crash) or possibly execute arbitrary code.
    (CVE-2014-8738)

    Hanno Bck discovered a stack-based buffer overflow in the ihex_scan function in libbfd in GNU binutils.
    An attacker could use this to craft input that could cause a denial of service (application crash).
    (CVE-2014-8503)

    Michal Zalewski discovered a stack-based buffer overflow in the srec_scan function in libbfd in GNU
    binutils. An attacker could use this to to craft input that could cause a denial of service (application
    crash); the GNU C library's Fortify Source printf protection should prevent the possibility of executing
    arbitrary code. (CVE-2014-8504)

    Michal Zalewski discovered that the srec_scan function in libbfd in GNU binutils allowed out-of-bounds
    reads. An attacker could use this to craft input to cause a denial of service. This issue only affected
    Ubuntu 14.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 10.04 LTS. (CVE-2014-8484)

    Sang Kil Cha discovered multiple integer overflows in the _objalloc_alloc function and objalloc_alloc
    macro in binutils. This could allow an attacker to cause a denial of service (application crash). This
    issue only affected Ubuntu 12.04 LTS and Ubuntu 10.04 LTS. (CVE-2012-3509)

    Alexander Cherepanov and Hanno Bck discovered multiple additional out-of-bounds reads and writes in GNU
    binutils. An attacker could use these to craft input that could cause a denial of service (application
    crash) or possibly execute arbitrary code. A few of these issues may be limited in exposure to a denial of
    service (application abort) by the GNU C library's Fortify Source printf protection.

    The strings(1) utility in GNU binutils used libbfd by default when examining executable object files;
    unfortunately, libbfd was not originally developed with the expectation of hostile input. As a defensive
    measure, the behavior of strings has been changed to default to 'strings --all' behavior, which does not
    use libbfd; use the new argument to strings, '--data', to recreate the old behavior.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2496-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8504");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-8738");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-static-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'binutils', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-dev', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-source', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-static', 'pkgver': '2.24-5ubuntu3.1'},
    {'osver': '14.04', 'pkgname': 'binutils-static-udeb', 'pkgver': '2.24-5ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-dev / binutils-multiarch / etc');
}
