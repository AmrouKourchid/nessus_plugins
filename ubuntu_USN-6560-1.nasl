#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6560-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187105);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2023-28531", "CVE-2023-48795");
  script_xref(name:"IAVA", value:"2023-A-0152-S");
  script_xref(name:"USN", value:"6560-1");
  script_xref(name:"IAVA", value:"2023-A-0703");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : OpenSSH vulnerabilities (USN-6560-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6560-1 advisory.

    Fabian Bumer, Marcus Brinkmann, Jrg Schwenk discovered that the SSH protocol was vulnerable to a
    prefix truncation attack. If a remote attacker was able to intercept SSH communications, extension
    negotiation messages could be truncated, possibly leading to certain algorithms and features being
    downgraded. This issue is known as the Terrapin attack. This update adds protocol extensions to mitigate
    this issue. (CVE-2023-48795)

    Luci Stanescu discovered that OpenSSH incorrectly added destination constraints when smartcard keys were
    added to ssh-agent, contrary to expectations. This issue only affected Ubuntu 22.04 LTS, and Ubuntu 23.04.
    (CVE-2023-28531)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6560-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28531");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-sftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'openssh-client', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'openssh-server', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'openssh-tests', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'ssh', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:8.2p1-4ubuntu0.10'},
    {'osver': '22.04', 'pkgname': 'openssh-client', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '22.04', 'pkgname': 'openssh-server', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '22.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '22.04', 'pkgname': 'openssh-tests', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '22.04', 'pkgname': 'ssh', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '22.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:8.9p1-3ubuntu0.5'},
    {'osver': '23.04', 'pkgname': 'openssh-client', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.04', 'pkgname': 'openssh-server', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.04', 'pkgname': 'openssh-tests', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.04', 'pkgname': 'ssh', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:9.0p1-1ubuntu8.6'},
    {'osver': '23.10', 'pkgname': 'openssh-client', 'pkgver': '1:9.3p1-1ubuntu3.1'},
    {'osver': '23.10', 'pkgname': 'openssh-server', 'pkgver': '1:9.3p1-1ubuntu3.1'},
    {'osver': '23.10', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:9.3p1-1ubuntu3.1'},
    {'osver': '23.10', 'pkgname': 'openssh-tests', 'pkgver': '1:9.3p1-1ubuntu3.1'},
    {'osver': '23.10', 'pkgname': 'ssh', 'pkgver': '1:9.3p1-1ubuntu3.1'},
    {'osver': '23.10', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:9.3p1-1ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh-client / openssh-server / openssh-sftp-server / etc');
}
