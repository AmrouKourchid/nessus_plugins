#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2784-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86650);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-4734",
    "CVE-2015-4803",
    "CVE-2015-4805",
    "CVE-2015-4806",
    "CVE-2015-4835",
    "CVE-2015-4840",
    "CVE-2015-4842",
    "CVE-2015-4843",
    "CVE-2015-4844",
    "CVE-2015-4860",
    "CVE-2015-4868",
    "CVE-2015-4872",
    "CVE-2015-4881",
    "CVE-2015-4882",
    "CVE-2015-4883",
    "CVE-2015-4893",
    "CVE-2015-4903",
    "CVE-2015-4911"
  );
  script_xref(name:"USN", value:"2784-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenJDK 7 vulnerabilities (USN-2784-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2784-1 advisory.

    Multiple vulnerabilities were discovered in the OpenJDK JRE related to information disclosure, data
    integrity and availability. An attacker could exploit these to cause a denial of service or expose
    sensitive data over the network. (CVE-2015-4805, CVE-2015-4835, CVE-2015-4843, CVE-2015-4844,
    CVE-2015-4860, CVE-2015-4868, CVE-2015-4881, CVE-2015-4883)

    A vulnerability was discovered in the OpenJDK JRE related to information disclosure and data integrity. An
    attacker could exploit this to expose sensitive data over the network. (CVE-2015-4806)

    A vulnerability was discovered in the OpenJDK JRE related to data integrity. An attacker could exploit
    this expose sensitive data over the network. (CVE-2015-4872)

    Multiple vulnerabilities were discovered in the OpenJDK JRE related to information disclosure. An attacker
    could exploit these to expose sensitive data over the network. (CVE-2015-4734, CVE-2015-4840,
    CVE-2015-4842, CVE-2015-4903)

    Multiple vulnerabilities were discovered in the OpenJDK JRE related to availability. An attacker could
    exploit these to cause a denial of service. (CVE-2015-4803, CVE-2015-4882, CVE-2015-4893, CVE-2015-4911)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2784-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4883");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-4806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-source");
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
    {'osver': '14.04', 'pkgname': 'icedtea-7-jre-jamvm', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-demo', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jdk', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-headless', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-lib', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-zero', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-source', 'pkgver': '7u85-2.6.1-5ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icedtea-7-jre-jamvm / openjdk-7-demo / openjdk-7-jdk / etc');
}
