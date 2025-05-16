#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2187-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73801);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-0429",
    "CVE-2014-0446",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0456",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-1876",
    "CVE-2014-2397",
    "CVE-2014-2398",
    "CVE-2014-2402",
    "CVE-2014-2403",
    "CVE-2014-2412",
    "CVE-2014-2413",
    "CVE-2014-2414",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427"
  );
  script_bugtraq_id(
    65568,
    66856,
    66866,
    66873,
    66877,
    66879,
    66881,
    66883,
    66887,
    66891,
    66893,
    66894,
    66898,
    66899,
    66902,
    66903,
    66905,
    66909,
    66910,
    66914,
    66916,
    66917,
    66918,
    66920
  );
  script_xref(name:"USN", value:"2187-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenJDK 7 vulnerabilities (USN-2187-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2187-1 advisory.

    Several vulnerabilities were discovered in the OpenJDK JRE related to information disclosure, data
    integrity and availability. An attacker could exploit these to cause a denial of service or expose
    sensitive data over the network. (CVE-2014-0429, CVE-2014-0446, CVE-2014-0451, CVE-2014-0452,
    CVE-2014-0454, CVE-2014-0455, CVE-2014-0456, CVE-2014-0457, CVE-2014-0458, CVE-2014-0461, CVE-2014-2397,
    CVE-2014-2402, CVE-2014-2412, CVE-2014-2414, CVE-2014-2421, CVE-2014-2423, CVE-2014-2427)

    Two vulnerabilities were discovered in the OpenJDK JRE related to information disclosure and data
    integrity. An attacker could exploit these to expose sensitive data over the network. (CVE-2014-0453,
    CVE-2014-0460)

    A vulnerability was discovered in the OpenJDK JRE related to availability. An attacker could exploit this
    to cause a denial of service. (CVE-2014-0459)

    Jakub Wilk discovered that the OpenJDK JRE incorrectly handled temporary files. A local attacker could
    possibly use this issue to overwrite arbitrary files. In the default installation of Ubuntu, this should
    be prevented by the Yama link restrictions. (CVE-2014-1876)

    Two vulnerabilities were discovered in the OpenJDK JRE related to data integrity. (CVE-2014-2398,
    CVE-2014-2413)

    A vulnerability was discovered in the OpenJDK JRE related to information disclosure. An attacker could
    exploit this to expose sensitive data over the network. (CVE-2014-2403)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2187-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2421");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-2423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/01");

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

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'icedtea-7-jre-jamvm', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-demo', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jdk', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-headless', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-lib', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-zero', 'pkgver': '7u55-2.4.7-1ubuntu1'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-source', 'pkgver': '7u55-2.4.7-1ubuntu1'}
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
