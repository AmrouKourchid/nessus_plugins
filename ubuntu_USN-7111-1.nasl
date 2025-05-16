#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7111-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211363);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24536",
    "CVE-2023-39323",
    "CVE-2023-45288",
    "CVE-2023-45290",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24789",
    "CVE-2024-24791",
    "CVE-2024-34155",
    "CVE-2024-34156",
    "CVE-2024-34158"
  );
  script_xref(name:"USN", value:"7111-1");

  script_name(english:"Ubuntu 22.04 LTS : Go vulnerabilities (USN-7111-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-7111-1 advisory.

    Philippe Antoine discovered that Go incorrectly handled crafted HTTP/2 streams. An attacker could possibly
    use this issue to cause a denial of service. (CVE-2022-41723)

    Marten Seemann discovered that Go did not properly manage memory under certain circumstances. An attacker
    could possibly use this issue to cause a panic resulting in a denial of service. (CVE-2022-41724)

    Ameya Darshan and Jakob Ackermann discovered that Go did not properly validate the amount of memory and
    disk files ReadForm can consume. An attacker could possibly use this issue to cause a panic resulting in a
    denial of service. (CVE-2022-41725)

    Jakob Ackermann discovered that Go incorrectly handled multipart forms. An attacker could possibly use
    this issue to consume an excessive amount of resources, resulting in a denial of service. (CVE-2023-24536)

    It was discovered that Go did not properly validate the //go:cgo_ directives during compilation. An
    attacker could possibly use this issue to inject arbitrary code during compile time. (CVE-2023-39323)

    Bartek Nowotarski was discovered that the Go net/http module did not properly handle the requests when
    request's headers exceed MaxHeaderBytes. An attacker could possibly use this issue to cause a panic
    resulting into a denial of service. (CVE-2023-45288)

    Bartek Nowotarski discovered that the Go net/http module did not properly validate the total size of the
    parsed form when parsing a multipart form. An attacker could possibly use this issue to cause a panic
    resulting into a denial of service. (CVE-2023-45290)

    John Howard discovered that the Go crypto/x509 module did not properly handle a certificate chain which
    contains a certificate with an unknown public key algorithm. An attacker could possibly use this issue to
    cause a panic resulting into a denial of service. (CVE-2024-24783)

    Juho Nurminen discovered that the Go net/mail module did not properly handle comments within display names
    in the ParseAddressList function. An attacker could possibly use this issue to cause a panic resulting
    into a denial of service. (CVE-2024-24784)

    Yufan You discovered that the Go archive/zip module did not properly handle certain types of invalid zip
    files differs from the behavior of most zip implementations. An attacker could possibly use this issue to
    cause a panic resulting into a denial of service. (CVE-2024-24789)

    Geoff Franks discovered that the Go net/http module did not properly handle responses to requests with an
    Expect: 100-continue header under certain circumstances. An attacker could possibly use this issue to
    cause a denial of service. (CVE-2024-24791)

    It was discovered that the Go parser module did not properly handle deeply nested literal values. An
    attacker could possibly use this issue to cause a panic resulting in a denial of service. (CVE-2024-34155)

    Md Sakib Anwar discovered that the Go encoding/gob module did not properly handle message decoding under
    certain circumstances. An attacker could possibly use this issue to cause a panic resulting in a denial of
    service. (CVE-2024-34156)

    It was discovered that the Go build module did not properly handle certain build tag lines with deeply
    nested expressions. An attacker could possibly use this issue to cause a panic resulting in a denial of
    service. (CVE-2024-34158)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7111-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-1.17, golang-1.17-go and / or golang-1.17-src packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39323");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.17-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.17-src");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'golang-1.17', 'pkgver': '1.17.13-3ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'golang-1.17-go', 'pkgver': '1.17.13-3ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'golang-1.17-src', 'pkgver': '1.17.13-3ubuntu1.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.17 / golang-1.17-go / golang-1.17-src');
}
