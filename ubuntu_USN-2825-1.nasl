#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2825-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87320);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-6765",
    "CVE-2015-6766",
    "CVE-2015-6767",
    "CVE-2015-6768",
    "CVE-2015-6769",
    "CVE-2015-6770",
    "CVE-2015-6771",
    "CVE-2015-6772",
    "CVE-2015-6773",
    "CVE-2015-6777",
    "CVE-2015-6782",
    "CVE-2015-6784",
    "CVE-2015-6785",
    "CVE-2015-6786",
    "CVE-2015-6787",
    "CVE-2015-8478"
  );
  script_xref(name:"USN", value:"2825-1");

  script_name(english:"Ubuntu 14.04 LTS : Oxide vulnerabilities (USN-2825-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2825-1 advisory.

    Multiple use-after-free bugs were discovered in the application cache implementation in Chromium. If a
    user were tricked in to opening a specially crafted website, an attacker could potentially exploit these
    to cause a denial of service via application crash, or execute arbitrary code with the privileges of the
    user invoking the program. (CVE-2015-6765, CVE-2015-6766, CVE-2015-6767)

    Several security issues were discovered in the DOM implementation in Chromium. If a user were tricked in
    to opening a specially crafted website, an attacker could potentially exploit these to bypass same origin
    restrictions. (CVE-2015-6768, CVE-2015-6770)

    A security issue was discovered in the provisional-load commit implementation in Chromium. If a user were
    tricked in to opening a specially crafted website, an attacker could potentially exploit this to bypass
    same origin restrictions. (CVE-2015-6769)

    An out-of-bounds read was discovered in the array map and filter operations in V8 in some circumstances.
    If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit
    this to cause a denial of service via renderer crash. (CVE-2015-6771)

    It was discovered that the DOM implementation in Chromium does not prevent javascript: URL navigation
    while a document is being detached. If a user were tricked in to opening a specially crafted website, an
    attacker could potentially exploit this to bypass same origin restrictions. (CVE-2015-6772)

    An out-of bounds read was discovered in Skia in some cirumstances. If a user were tricked in to opening a
    specially crafted website, an attacker could potentially exploit this to cause a denial of service via
    renderer crash. (CVE-2015-6773)

    A use-after-free was discovered in the DOM implementation in Chromium. If a user were tricked in to
    opening a specially crafted website, an attacker could potentially exploit this to cause a denial of
    service via renderer crash or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-6777)

    It was discovered that the Document::open function in Chromium did not ensure that page-dismissal event
    handling is compatible with modal dialog blocking. If a user were tricked in to opening a specially
    crafted website, an attacker could potentially exploit this to spoof application UI content.
    (CVE-2015-6782)

    It was discovered that the page serializer in Chromium mishandled MOTW comments for URLs in some
    circumstances. An attacker could potentially exploit this to inject HTML content. (CVE-2015-6784)

    It was discovered that the Content Security Policy (CSP) implementation in Chromium accepted an x.y
    hostname as a match for a *.x.y pattern. An attacker could potentially exploit this to bypass intended
    access restrictions. (CVE-2015-6785)

    It was discovered that the Content Security Policy (CSP) implementation in Chromium accepted blob:, data:
    and filesystem: URLs as a match for a * pattern. An attacker could potentially exploit this to bypass
    intended access restrictions. (CVE-2015-6786)

    Multiple security issues were discovered in Chromium. If a user were tricked in to opening a specially
    crafted website, an attacker could potentially exploit these to read uninitialized memory, cause a denial
    of service via application crash or execute arbitrary code with the privileges of the user invoking the
    program. (CVE-2015-6787)

    Multiple security issues were discovered in V8. If a user were tricked in to opening a specially crafted
    website, an attacker could potentially exploit these to read uninitialized memory, cause a denial of
    service via renderer crash or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-8478)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2825-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6787");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-8478");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtquick0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqmlscene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqt-qmlplugin");
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
    {'osver': '14.04', 'pkgname': 'liboxideqt-qmlplugin', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'liboxideqtcore0', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'liboxideqtquick0', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'oxideqmlscene', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'oxideqt-chromedriver', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'oxideqt-codecs', 'pkgver': '1.11.3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'oxideqt-codecs-extra', 'pkgver': '1.11.3-0ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liboxideqt-qmlplugin / liboxideqtcore0 / liboxideqtquick0 / etc');
}
