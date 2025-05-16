#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5822-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170562);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-20251",
    "CVE-2022-3437",
    "CVE-2022-37966",
    "CVE-2022-37967",
    "CVE-2022-38023",
    "CVE-2022-42898",
    "CVE-2022-45141"
  );
  script_xref(name:"USN", value:"5822-1");
  script_xref(name:"IAVA", value:"2022-A-0447-S");
  script_xref(name:"IAVA", value:"2022-A-0495-S");
  script_xref(name:"IAVA", value:"2023-A-0004-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Samba vulnerabilities (USN-5822-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5822-1 advisory.

    It was discovered that Samba incorrectly handled the bad password count logic. A remote attacker could
    possibly use this issue to bypass bad passwords lockouts. This issue was only addressed in Ubuntu 22.10.
    (CVE-2021-20251)

    Evgeny Legerov discovered that Samba incorrectly handled buffers in certain GSSAPI routines of Heimdal. A
    remote attacker could possibly use this issue to cause Samba to crash, resulting in a denial of service.
    (CVE-2022-3437)

    Tom Tervoort discovered that Samba incorrectly used weak rc4-hmac Kerberos keys. A remote attacker could
    possibly use this issue to elevate privileges. (CVE-2022-37966, CVE-2022-37967)

    It was discovered that Samba supported weak RC4/HMAC-MD5 in NetLogon Secure Channel. A remote attacker
    could possibly use this issue to elevate privileges. (CVE-2022-38023)

    Greg Hudson discovered that Samba incorrectly handled PAC parsing. On 32-bit systems, a remote attacker
    could use this issue to escalate privileges, or possibly execute arbitrary code. (CVE-2022-42898)

    Joseph Sutton discovered that Samba could be forced to issue rc4-hmac encrypted Kerberos tickets. A remote
    attacker could possibly use this issue to escalate privileges. This issue only affected Ubuntu 20.04 LTS
    and Ubuntu 22.04 LTS. (CVE-2022-45141)

    WARNING: The fixes included in these updates introduce several important behavior changes which may cause
    compatibility problems interacting with systems still expecting the former behavior. Please see the
    following upstream advisories for more information:

    https://www.samba.org/samba/security/CVE-2022-37966.html
    https://www.samba.org/samba/security/CVE-2022-37967.html
    https://www.samba.org/samba/security/CVE-2022-38023.html

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5822-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45141");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.13.17~dfsg-0ubuntu1.20.04.4'},
    {'osver': '22.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
