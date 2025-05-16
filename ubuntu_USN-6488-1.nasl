#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6488-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186013);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2023-41913");
  script_xref(name:"USN", value:"6488-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : strongSwan vulnerability (USN-6488-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by a vulnerability
as referenced in the USN-6488-1 advisory.

    Florian Picca discovered that strongSwan incorrectly handled certain DH public values. A remote attacker
    could use this issue to cause strongSwan to crash, resulting in a denial of service, or possibly execute
    arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6488-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:charon-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:charon-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-extauth-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-charon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-libcharon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-scepclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-swanctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-ifmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-server");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'charon-cmd', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'charon-systemd', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libcharon-standard-plugins', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libstrongswan', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-scepclient', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-base', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-client', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-ifmap', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-pdp', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-server', 'pkgver': '5.8.2-1ubuntu3.6'},
    {'osver': '22.04', 'pkgname': 'charon-cmd', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'charon-systemd', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libstrongswan', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-scepclient', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.9.5-2ubuntu2.2'},
    {'osver': '23.04', 'pkgname': 'charon-cmd', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'charon-systemd', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'libstrongswan', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.9.8-3ubuntu4.1'},
    {'osver': '23.10', 'pkgname': 'charon-cmd', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'charon-systemd', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libstrongswan', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-charon', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-nm', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-pki', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-starter', 'pkgver': '5.9.11-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.9.11-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'charon-cmd / charon-systemd / libcharon-extauth-plugins / etc');
}
