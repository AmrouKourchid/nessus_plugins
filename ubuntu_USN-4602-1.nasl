##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4602-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141913);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"USN", value:"4602-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Perl vulnerabilities (USN-4602-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4602-1 advisory.

    ManhND discovered that Perl incorrectly handled certain regular expressions. In environments where
    untrusted regular expressions are evaluated, a remote attacker could possibly use this issue to cause Perl
    to crash, resulting in a denial of service, or possibly execute arbitrary code. (CVE-2020-10543)

    Hugo van der Sanden and Slaven Rezic discovered that Perl incorrectly handled certain regular expressions.
    In environments where untrusted regular expressions are evaluated, a remote attacker could possibly use
    this issue to cause Perl to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2020-10878)

    Sergey Aleynikov discovered that Perl incorrectly handled certain regular expressions. In environments
    where untrusted regular expressions are evaluated, a remote attacker could possibly use this issue to
    cause Perl to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2020-12723)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4602-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl5.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl5.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl5.30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-modules-5.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-modules-5.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-modules-5.30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libperl-dev', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'libperl5.22', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'perl', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'perl-base', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'perl-debug', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '16.04', 'pkgname': 'perl-modules-5.22', 'pkgver': '5.22.1-9ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'libperl-dev', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'libperl5.26', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'perl', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'perl-base', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'perl-debug', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'perl-modules-5.26', 'pkgver': '5.26.1-6ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'libperl-dev', 'pkgver': '5.30.0-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libperl5.30', 'pkgver': '5.30.0-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'perl', 'pkgver': '5.30.0-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'perl-base', 'pkgver': '5.30.0-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'perl-debug', 'pkgver': '5.30.0-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'perl-modules-5.30', 'pkgver': '5.30.0-9ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libperl-dev / libperl5.22 / libperl5.26 / libperl5.30 / perl / etc');
}
