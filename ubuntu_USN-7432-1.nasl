#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7432-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234139);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2025-2784",
    "CVE-2025-32050",
    "CVE-2025-32051",
    "CVE-2025-32052",
    "CVE-2025-32053"
  );
  script_xref(name:"USN", value:"7432-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : libsoup vulnerabilities (USN-7432-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7432-1 advisory.

    It was discovered that libsoup could be made to read out of bounds. An attacker could possibly use this
    issue to cause applications using libsoup to crash, resulting in a denial of service. (CVE-2025-2784,
    CVE-2025-32050, CVE-2025-32052, CVE-2025-32053)

    It was discovered that libsoup could be made to dereference invalid memory. An attacker could possibly use
    this issue to cause applications using libsoup to crash, resulting in a denial of service.
    (CVE-2025-32051)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7432-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-soup-2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-soup-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-3.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-3.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-3.0-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-gnome-2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-gnome2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup-gnome2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup2.4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoup2.4-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-soup-2.4', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsoup-gnome2.4-1', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsoup-gnome2.4-dev', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsoup2.4-1', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsoup2.4-dev', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsoup2.4-tests', 'pkgver': '2.70.0-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'gir1.2-soup-2.4', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'gir1.2-soup-3.0', 'pkgver': '3.0.7-0ubuntu1+esm2'},
    {'osver': '22.04', 'pkgname': 'libsoup-3.0-0', 'pkgver': '3.0.7-0ubuntu1+esm2'},
    {'osver': '22.04', 'pkgname': 'libsoup-3.0-common', 'pkgver': '3.0.7-0ubuntu1+esm2'},
    {'osver': '22.04', 'pkgname': 'libsoup-3.0-dev', 'pkgver': '3.0.7-0ubuntu1+esm2'},
    {'osver': '22.04', 'pkgname': 'libsoup-3.0-tests', 'pkgver': '3.0.7-0ubuntu1+esm2'},
    {'osver': '22.04', 'pkgname': 'libsoup-gnome2.4-1', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsoup-gnome2.4-dev', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsoup2.4-1', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsoup2.4-common', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsoup2.4-dev', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsoup2.4-tests', 'pkgver': '2.74.2-3ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gir1.2-soup-2.4', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'gir1.2-soup-3.0', 'pkgver': '3.4.4-5ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-2.4-1', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-3.0-0', 'pkgver': '3.4.4-5ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-3.0-common', 'pkgver': '3.4.4-5ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-3.0-dev', 'pkgver': '3.4.4-5ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-3.0-tests', 'pkgver': '3.4.4-5ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-gnome-2.4-1', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'libsoup-gnome2.4-dev', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'libsoup2.4-common', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'libsoup2.4-dev', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.04', 'pkgname': 'libsoup2.4-tests', 'pkgver': '2.74.3-6ubuntu1.2'},
    {'osver': '24.10', 'pkgname': 'gir1.2-soup-2.4', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'gir1.2-soup-3.0', 'pkgver': '3.6.0-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-2.4-1', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-3.0-0', 'pkgver': '3.6.0-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-3.0-common', 'pkgver': '3.6.0-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-3.0-dev', 'pkgver': '3.6.0-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-3.0-tests', 'pkgver': '3.6.0-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-gnome-2.4-1', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup-gnome2.4-dev', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup2.4-common', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup2.4-dev', 'pkgver': '2.74.3-7ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libsoup2.4-tests', 'pkgver': '2.74.3-7ubuntu0.2'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-soup-2.4 / gir1.2-soup-3.0 / libsoup-2.4-1 / libsoup-3.0-0 / etc');
}
