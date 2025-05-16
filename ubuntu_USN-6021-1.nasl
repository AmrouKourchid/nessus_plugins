#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6021-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174331);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-1528",
    "CVE-2023-1529",
    "CVE-2023-1530",
    "CVE-2023-1531",
    "CVE-2023-1532",
    "CVE-2023-1533",
    "CVE-2023-1534",
    "CVE-2023-1810",
    "CVE-2023-1811",
    "CVE-2023-1812",
    "CVE-2023-1813",
    "CVE-2023-1814",
    "CVE-2023-1815",
    "CVE-2023-1816",
    "CVE-2023-1818",
    "CVE-2023-1819",
    "CVE-2023-1820",
    "CVE-2023-1821",
    "CVE-2023-1822",
    "CVE-2023-1823"
  );
  script_xref(name:"USN", value:"6021-1");

  script_name(english:"Ubuntu 18.04 LTS : Chromium vulnerabilities (USN-6021-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6021-1 advisory.

    It was discovered that Chromium did not properly manage memory in several components. A remote attacker
    could possibly use this issue to corrupt memory via a crafted HTML page, resulting in a denial of service,
    or possibly execute arbitrary code. (CVE-2023-1528, CVE-2023-1530, CVE-2023-1531, CVE-2023-1533,
    CVE-2023-1811, CVE-2023-1815, CVE-2023-1818)

    It was discovered that Chromium could be made to access memory out of bounds in WebHID. A remote attacker
    could possibly use this issue to corrupt memory via a malicious HID device, resulting in a denial of
    service, or possibly execute arbitrary code. (CVE-2023-1529)

    It was discovered that Chromium could be made to access memory out of bounds in several components. A
    remote attacker could possibly use this issue to corrupt memory via a crafted HTML page, resulting in a
    denial of service, or possibly execute arbitrary code. (CVE-2023-1532, CVE-2023-1534, CVE-2023-1810,
    CVE-2023-1812, CVE-2023-1819, CVE-2023-1820)

    It was discovered that Chromium contained an inappropriate implementation in the Extensions component. A
    remote attacker who convinced a user to install a malicious extension could possibly use this issue to
    bypass file access restrictions via a crafted HTML page. (CVE-2023-1813)

    It was discovered that Chromium did not properly validate untrusted input in the Safe Browsing component.
    A remote attacker could possibly use this issue to bypass download checking via a crafted HTML page.
    (CVE-2023-1814)

    It was discovered that Chromium contained an inappropriate implementation in the Picture In Picture
    component. A remote attacker could possibly use this issue to perform navigation spoofing via a crafted
    HTML page. (CVE-2023-1816)

    It was discovered that Chromium contained an inappropriate implementation in the WebShare component. A
    remote attacker could possibly use this issue to hide the contents of the Omnibox (URL bar) via a crafted
    HTML page. (CVE-2023-1821)

    It was discovered that Chromium contained an inappropriate implementation in the Navigation component. A
    remote attacker could possibly use this issue to perform domain spoofing via a crafted HTML page.
    (CVE-2023-1822)

    It was discovered that Chromium contained an inappropriate implementation in the FedCM component. A remote
    attacker could possibly use this issue to bypass navigation restrictions via a crafted HTML page.
    (CVE-2023-1823)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6021-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1820");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-browser-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-codecs-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-codecs-ffmpeg-extra");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'chromium-browser', 'pkgver': '112.0.5615.49-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-browser-l10n', 'pkgver': '112.0.5615.49-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-chromedriver', 'pkgver': '112.0.5615.49-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg', 'pkgver': '112.0.5615.49-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg-extra', 'pkgver': '112.0.5615.49-0ubuntu0.18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium-browser / chromium-browser-l10n / chromium-chromedriver / etc');
}
