#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5881-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171733);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2023-0471",
    "CVE-2023-0472",
    "CVE-2023-0473",
    "CVE-2023-0474",
    "CVE-2023-0696",
    "CVE-2023-0698",
    "CVE-2023-0699",
    "CVE-2023-0700",
    "CVE-2023-0701",
    "CVE-2023-0702",
    "CVE-2023-0703",
    "CVE-2023-0704",
    "CVE-2023-0705"
  );
  script_xref(name:"USN", value:"5881-1");

  script_name(english:"Ubuntu 18.04 LTS : Chromium vulnerabilities (USN-5881-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5881-1 advisory.

    It was discovered that Chromium did not properly manage memory. A remote attacker could possibly use these
    issues to cause a denial of service or execute arbitrary code via a crafted HTML page. (CVE-2023-0471,
    CVE-2023-0472, CVE-2023-0473, CVE-2023-0696, CVE-2023-0698, CVE-2023-0699, CVE-2023-0702, CVE-2023-0705)

    It was discovered that Chromium did not properly manage memory. A remote attacker who convinced a user to
    install a malicious extension could possibly use this issue to corrupt memory via a Chrome web app.
    (CVE-2023-0474)

    It was discovered that Chromium contained an inappropriate implementation in the Download component. A
    remote attacker could possibly use this issue to spoof contents of the Omnibox (URL bar) via a crafted
    HTML page. (CVE-2023-0700)

    It was discovered that Chromium did not properly manage memory. A remote attacker who convinced a user to
    engage in specific UI interactions could possibly use these issues to cause a denial of service or execute
    arbitrary code. (CVE-2023-0701, CVE-2023-0703)

    It was discovered that Chromium insufficiently enforced policies. A remote attacker could possibly use
    this issue to bypass same origin policy and proxy settings via a crafted HTML page. (CVE-2023-0704)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5881-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/21");

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
    {'osver': '18.04', 'pkgname': 'chromium-browser', 'pkgver': '110.0.5481.100-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-browser-l10n', 'pkgver': '110.0.5481.100-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-chromedriver', 'pkgver': '110.0.5481.100-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg', 'pkgver': '110.0.5481.100-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg-extra', 'pkgver': '110.0.5481.100-0ubuntu0.18.04.1'}
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
