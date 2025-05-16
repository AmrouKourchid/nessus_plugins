#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6038-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174750);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-41715",
    "CVE-2022-41717",
    "CVE-2023-24534",
    "CVE-2023-24537",
    "CVE-2023-24538"
  );
  script_xref(name:"USN", value:"6038-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Go vulnerabilities (USN-6038-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6038-1 advisory.

    It was discovered that the Go net/http module incorrectly handled Transfer-Encoding headers in the HTTP/1
    client. A remote attacker could possibly use this issue to perform an HTTP Request Smuggling attack.
    (CVE-2022-1705)

    It was discovered that Go did not properly manage memory under certain circumstances. An attacker could
    possibly use this issue to cause a panic resulting into a denial of service. (CVE-2022-1962,
    CVE-2022-27664, CVE-2022-28131, CVE-2022-30630, CVE-2022-30631, CVE-2022-30632, CVE-2022-30633,
    CVE-2022-30635, CVE-2022-32189, CVE-2022-41715, CVE-2022-41717, CVE-2023-24534, CVE-2023-24537)

    It was discovered that Go did not properly implemented the maximum size of file headers in Reader.Read. An
    attacker could possibly use this issue to cause a panic resulting into a denial of service.
    (CVE-2022-2879)

    It was discovered that the Go net/http module incorrectly handled query parameters in requests forwarded
    by ReverseProxy. A remote attacker could possibly use this issue to perform an HTTP Query Parameter
    Smuggling attack. (CVE-2022-2880)

    It was discovered that Go did not properly manage the permissions for Faccessat function. A attacker could
    possibly use this issue to expose sensitive information. (CVE-2022-29526)

    It was discovered that Go did not properly generate the values for ticket_age_add in session tickets. An
    attacker could possibly use this issue to observe TLS handshakes to correlate successive connections by
    comparing ticket ages during session resumption. (CVE-2022-30629)

    It was discovered that Go did not properly manage client IP addresses in net/http. An attacker could
    possibly use this issue to cause ReverseProxy to set the client IP as the value of the X-Forwarded-For
    header. (CVE-2022-32148)

    It was discovered that Go did not properly validate backticks (`) as Javascript string delimiters, and do
    not escape them as expected. An attacker could possibly use this issue to inject arbitrary Javascript code
    into the Go template. (CVE-2023-24538)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6038-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-1.18, golang-1.18-go and / or golang-1.18-src packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29526");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-24538");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~18.04.4'},
    {'osver': '20.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1~20.04.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.18', 'pkgver': '1.18.1-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.18-go', 'pkgver': '1.18.1-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.18-src', 'pkgver': '1.18.1-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.18 / golang-1.18-go / golang-1.18-src');
}
