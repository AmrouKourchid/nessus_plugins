#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6574-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187937);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-39326",
    "CVE-2023-44487",
    "CVE-2023-45285"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"USN", value:"6574-1");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : Go vulnerabilities (USN-6574-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6574-1 advisory.

    Takeshi Kaneko discovered that Go did not properly handle comments and special tags in the script context
    of html/template module. An attacker could possibly use this issue to inject Javascript code and perform a
    cross site scripting attack. This issue only affected Go 1.20 in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and
    Ubuntu 23.04. (CVE-2023-39318, CVE-2023-39319)

    It was discovered that Go did not properly validate the //go:cgo_ directives during compilation. An
    attacker could possibly use this issue to inject arbitrary code during compile time. (CVE-2023-39323)

    It was discovered that Go did not limit the number of simultaneously executing handler goroutines in the
    net/http module. An attacker could possibly use this issue to cause a panic resulting into a denial of
    service. (CVE-2023-39325, CVE-2023-44487)

    It was discovered that the Go net/http module did not properly validate the chunk extensions reading from
    a request or response body. An attacker could possibly use this issue to read sensitive information.
    (CVE-2023-39326)

    It was discovered that Go did not properly validate the insecure git:// protocol when using go get to
    fetch a module with the .git suffix. An attacker could possibly use this issue to bypass secure protocol
    checks. (CVE-2023-45285)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6574-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45285");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39323");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.20-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.20-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.21-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-1.21-src");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'golang-1.20', 'pkgver': '1.20.3-1ubuntu0.1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'golang-1.20-go', 'pkgver': '1.20.3-1ubuntu0.1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'golang-1.20-src', 'pkgver': '1.20.3-1ubuntu0.1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'golang-1.21', 'pkgver': '1.21.1-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.21-go', 'pkgver': '1.21.1-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-1.21-src', 'pkgver': '1.21.1-1~ubuntu20.04.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.20', 'pkgver': '1.20.3-1ubuntu0.1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.20-go', 'pkgver': '1.20.3-1ubuntu0.1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.20-src', 'pkgver': '1.20.3-1ubuntu0.1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'golang-1.21', 'pkgver': '1.21.1-1~ubuntu22.04.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.21-go', 'pkgver': '1.21.1-1~ubuntu22.04.2'},
    {'osver': '22.04', 'pkgname': 'golang-1.21-src', 'pkgver': '1.21.1-1~ubuntu22.04.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.20', 'pkgver': '1.20.3-1ubuntu0.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.20-go', 'pkgver': '1.20.3-1ubuntu0.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.20-src', 'pkgver': '1.20.3-1ubuntu0.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.21', 'pkgver': '1.21.1-1~ubuntu23.04.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.21-go', 'pkgver': '1.21.1-1~ubuntu23.04.2'},
    {'osver': '23.04', 'pkgname': 'golang-1.21-src', 'pkgver': '1.21.1-1~ubuntu23.04.2'},
    {'osver': '23.10', 'pkgname': 'golang-1.20', 'pkgver': '1.20.8-1ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'golang-1.20-go', 'pkgver': '1.20.8-1ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'golang-1.20-src', 'pkgver': '1.20.8-1ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'golang-1.21', 'pkgver': '1.21.1-1ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'golang-1.21-go', 'pkgver': '1.21.1-1ubuntu0.23.10.1'},
    {'osver': '23.10', 'pkgname': 'golang-1.21-src', 'pkgver': '1.21.1-1ubuntu0.23.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-1.20 / golang-1.20-go / golang-1.20-src / golang-1.21 / etc');
}
