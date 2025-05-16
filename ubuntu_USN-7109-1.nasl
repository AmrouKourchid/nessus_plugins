#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7109-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210950);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24531",
    "CVE-2023-24536",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405",
    "CVE-2023-29406",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-45288",
    "CVE-2023-45290",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24785",
    "CVE-2024-24789",
    "CVE-2024-24790",
    "CVE-2024-24791",
    "CVE-2024-34155",
    "CVE-2024-34156",
    "CVE-2024-34158"
  );
  script_xref(name:"USN", value:"7109-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS : Go vulnerabilities (USN-7109-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-7109-1 advisory.

    Philippe Antoine discovered that Go incorrectly handled crafted HTTP/2 streams. An attacker could possibly
    use this issue to cause a denial of service. (CVE-2022-41723)

    Marten Seemann discovered that Go did not properly manage memory under certain circumstances. An attacker
    could possibly use this issue to cause a panic resulting in a denial of service. (CVE-2022-41724)

    Ameya Darshan and Jakob Ackermann discovered that Go did not properly validate the amount of memory and
    disk files ReadForm can consume. An attacker could possibly use this issue to cause a panic resulting in a
    denial of service. (CVE-2022-41725)

    Hunter Wittenborn discovered that Go incorrectly handled the sanitization of environment variables. An
    attacker could possibly use this issue to run arbitrary commands. (CVE-2023-24531)

    Jakob Ackermann discovered that Go incorrectly handled multipart forms. An attacker could possibly use
    this issue to consume an excessive amount of resources, resulting in a denial of service. (CVE-2023-24536)

    Juho Nurminen discovered that Go incorrectly handled certain special characters in directory or file
    paths. An attacker could possibly use this issue to inject code into the resulting binaries.
    (CVE-2023-29402)

    Vincent Dehors discovered that Go incorrectly handled permission bits. An attacker could possibly use this
    issue to read or write files with elevated privileges. (CVE-2023-29403)

    Juho Nurminen discovered that Go incorrectly handled certain compiler directives. An attacker could
    possibly use this issue to execute arbitrary code. (CVE-2023-29404)

    Juho Nurminen discovered that Go incorrectly handled certain crafted arguments. An attacker could possibly
    use this issue to execute arbitrary code at build time. (CVE-2023-29405)

    Bartek Nowotarski discovered that Go incorrectly validated the contents of host headers. A remote attacker
    could possibly use this issue to inject additional headers or entire requests. (CVE-2023-29406)

    Takeshi Kaneko discovered that Go did not properly handle comments and special tags in the script context
    of html/template module. An attacker could possibly use this issue to inject Javascript code and perform a
    cross-site scripting attack. (CVE-2023-39318, CVE-2023-39319)

    It was discovered that Go did not properly validate the //go:cgo_ directives during compilation. An
    attacker could possibly use this issue to inject arbitrary code during compile time. (CVE-2023-39323)

    It was discovered that Go did not limit the number of simultaneously executing handler goroutines in the
    net/http module. An attacker could possibly use this issue to cause a panic resulting in a denial of
    service. (CVE-2023-39325)

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

    It was discovered that the Go html/template module did not validate errors returned from MarshalJSON
    methods. An attacker could possibly use this issue to inject arbitrary code into the Go template.
    (CVE-2024-24785)

    Yufan You discovered that the Go archive/zip module did not properly handle certain types of invalid zip
    files differs from the behavior of most zip implementations. An attacker could possibly use this issue to
    cause a panic resulting into a denial of service. (CVE-2024-24789)

    Enze Wang and Jianjun Chen discovered that the Go net/netip module did not work as expected for
    IPv4-mapped IPv6 addresses in various Is methods. An attacker could possibly use this issue to cause a
    panic resulting into a denial of service. (CVE-2024-24790)

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7109-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-1.18, golang-1.18-go and / or golang-1.18-src packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.18-src");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~16.04.6+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~16.04.6+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~16.04.6+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~18.04.4+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~18.04.4+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~18.04.4+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1.2', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.18 / golang-1.18-go / golang-1.18-src');
}
