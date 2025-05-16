#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7061-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208702);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/10");

  script_cve_id(
    "CVE-2023-24531",
    "CVE-2023-24538",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405",
    "CVE-2023-29406",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39325",
    "CVE-2024-24785"
  );
  script_xref(name:"USN", value:"7061-1");

  script_name(english:"Ubuntu 22.04 LTS : Go vulnerabilities (USN-7061-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-7061-1 advisory.

    Hunter Wittenborn discovered that Go incorrectly handled the sanitization of environment variables. An
    attacker could possibly use this issue to run arbitrary commands. (CVE-2023-24531)

    Sohom Datta discovered that Go did not properly validate backticks (`) as Javascript string delimiters,
    and did not escape them as expected. An attacker could possibly use this issue to inject arbitrary
    Javascript code into the Go template. (CVE-2023-24538)

    Juho Nurminen discovered that Go incorrectly handled certain special characters in directory or file
    paths. An attacker could possibly use this issue to inject code into the resulting binaries.
    (CVE-2023-29402)

    Vincent Dehors discovered that Go incorrectly handled permission bits. An attacker could possibly use this
    issue to read or write files with elevated privileges. (CVE-2023-29403)

    Juho Nurminen discovered that Go incorrectly handled certain crafted arguments. An attacker could possibly
    use this issue to execute arbitrary code at build time. (CVE-2023-29405)

    It was discovered that Go incorrectly validated the contents of host headers. A remote attacker could
    possibly use this issue to inject additional headers or entire requests. (CVE-2023-29406)

    Takeshi Kaneko discovered that Go did not properly handle comments and special tags in the script context
    of html/template module. An attacker could possibly use this issue to inject Javascript code and perform a
    cross-site scripting attack. (CVE-2023-39318, CVE-2023-39319)

    It was discovered that Go did not limit the number of simultaneously executing handler goroutines in the
    net/http module. An attacker could possibly use this issue to cause a panic resulting in a denial of
    service. (CVE-2023-39325)

    It was discovered that the Go html/template module did not validate errors returned from MarshalJSON
    methods. An attacker could possibly use this issue to inject arbitrary code into the Go template.
    (CVE-2024-24785)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7061-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-1.17, golang-1.17-go and / or golang-1.17-src packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

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
    {'osver': '22.04', 'pkgname': 'golang-1.17', 'pkgver': '1.17.13-3ubuntu1.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.17-go', 'pkgver': '1.17.13-3ubuntu1.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.17-src', 'pkgver': '1.17.13-3ubuntu1.2'}
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
