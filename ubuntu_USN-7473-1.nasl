#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7473-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235067);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id("CVE-2025-46646");
  script_xref(name:"IAVB", value:"2025-B-0043");
  script_xref(name:"USN", value:"7473-1");

  script_name(english:"Ubuntu 24.04 LTS / 24.10 : Ghostscript vulnerability (USN-7473-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS / 24.10 host has packages installed that are affected by a vulnerability as referenced in
the USN-7473-1 advisory.

    It was discovered that Ghostscript incorrectly handled parsing certain PS files. An attacker could use
    this issue to cause Ghostscript to crash, resulting in a denial of service, or possibly bypass file path
    validation.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7473-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-46646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs10-common");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '24.04', 'pkgname': 'ghostscript', 'pkgver': '10.02.1~dfsg1-0ubuntu7.6'},
    {'osver': '24.04', 'pkgname': 'libgs-common', 'pkgver': '10.02.1~dfsg1-0ubuntu7.6'},
    {'osver': '24.04', 'pkgname': 'libgs-dev', 'pkgver': '10.02.1~dfsg1-0ubuntu7.6'},
    {'osver': '24.04', 'pkgname': 'libgs10', 'pkgver': '10.02.1~dfsg1-0ubuntu7.6'},
    {'osver': '24.04', 'pkgname': 'libgs10-common', 'pkgver': '10.02.1~dfsg1-0ubuntu7.6'},
    {'osver': '24.10', 'pkgname': 'ghostscript', 'pkgver': '10.03.1~dfsg1-0ubuntu2.3'},
    {'osver': '24.10', 'pkgname': 'libgs-common', 'pkgver': '10.03.1~dfsg1-0ubuntu2.3'},
    {'osver': '24.10', 'pkgname': 'libgs-dev', 'pkgver': '10.03.1~dfsg1-0ubuntu2.3'},
    {'osver': '24.10', 'pkgname': 'libgs10', 'pkgver': '10.03.1~dfsg1-0ubuntu2.3'},
    {'osver': '24.10', 'pkgname': 'libgs10-common', 'pkgver': '10.03.1~dfsg1-0ubuntu2.3'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / libgs-common / libgs-dev / libgs10 / libgs10-common');
}
