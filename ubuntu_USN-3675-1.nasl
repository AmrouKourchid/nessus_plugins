#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3675-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110475);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2018-12020", "CVE-2018-9234");
  script_xref(name:"USN", value:"3675-1");
  script_xref(name:"IAVA", value:"2018-A-0193");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : GnuPG vulnerabilities (USN-3675-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-3675-1 advisory.

    Marcus Brinkmann discovered that during decryption or verification, GnuPG did not properly filter out
    terminal sequences when reporting the original filename. An attacker could use this to specially craft a
    file that would cause an application parsing GnuPG output to incorrectly interpret the status of the
    cryptographic operation reported by GnuPG. (CVE-2018-12020)

    Lance Vick discovered that GnuPG did not enforce configurations where key certification required an
    offline primary Certify key. An attacker with access to a signing subkey could generate certifications
    that appeared to be valid. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-9234)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3675-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9234");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-wks-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-wks-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-win32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scdaemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dirmngr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'gnupg', 'pkgver': '1.4.16-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'gnupg-curl', 'pkgver': '1.4.16-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'gnupg-udeb', 'pkgver': '1.4.16-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'gpgv', 'pkgver': '1.4.16-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'gpgv-udeb', 'pkgver': '1.4.16-1ubuntu2.5'},
    {'osver': '16.04', 'pkgname': 'gnupg', 'pkgver': '1.4.20-1ubuntu3.2'},
    {'osver': '16.04', 'pkgname': 'gnupg-curl', 'pkgver': '1.4.20-1ubuntu3.2'},
    {'osver': '16.04', 'pkgname': 'gpgv', 'pkgver': '1.4.20-1ubuntu3.2'},
    {'osver': '16.04', 'pkgname': 'gpgv-udeb', 'pkgver': '1.4.20-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'dirmngr', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gnupg', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gnupg-agent', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gnupg-l10n', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gnupg-utils', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gnupg2', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpg', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpg-agent', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpg-wks-client', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpg-wks-server', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgconf', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgsm', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgv', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgv-static', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgv-udeb', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgv-win32', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'gpgv2', 'pkgver': '2.2.4-1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'scdaemon', 'pkgver': '2.2.4-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dirmngr / gnupg / gnupg-agent / gnupg-curl / gnupg-l10n / etc');
}
