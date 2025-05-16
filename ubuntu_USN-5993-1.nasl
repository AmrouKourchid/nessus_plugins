#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5993-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173794);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2023-0614", "CVE-2023-0922");
  script_xref(name:"IAVA", value:"2023-A-0167-S");
  script_xref(name:"USN", value:"5993-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Samba vulnerabilities (USN-5993-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5993-1 advisory.

    Demi Marie Obenour discovered that the Samba LDAP server incorrectly handled certain confidential
    attribute values. A remote authenticated attacker could possibly use this issue to obtain certain
    sensitive information. (CVE-2023-0614)

    Andrew Bartlett discovered that the Samba AD DC admin tool incorrectly sent passwords in cleartext. A
    remote attacker could possibly use this issue to obtain sensitive information. (CVE-2023-0922)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5993-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

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
    {'osver': '20.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu0.20.04.2'},
    {'osver': '22.04', 'pkgname': 'ctdb', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'python3-samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-common', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'smbclient', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'winbind', 'pkgver': '2:4.15.13+dfsg-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
