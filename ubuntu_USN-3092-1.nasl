#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3092-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93800);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2016-2119");
  script_xref(name:"USN", value:"3092-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Samba vulnerability (USN-3092-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-3092-1 advisory.

    Stefan Metzmacher discovered that Samba incorrectly handled certain flags in SMB2/3 client connections. A
    remote attacker could use this issue to disable client signing and impersonate servers by performing a
    machine-in-the-middle attack.

    Samba has been updated to 4.3.11 in Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. In addition to the security
    fix, the updated packages contain bug fixes, new features, and possibly incompatible changes.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3092-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libparse-pidl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbsharemodes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:registry-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libpam-smbpass', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libparse-pidl-perl', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libsmbsharemodes-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libsmbsharemodes0', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'python-samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-common', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'smbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.14.04.1'},
    {'osver': '16.04', 'pkgname': 'ctdb', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libnss-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libpam-winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libparse-pidl-perl', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libsmbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libsmbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libwbclient-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libwbclient0', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'python-samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'registry-tools', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-common', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-common-bin', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-dev', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-dsdb-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-libs', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-testsuite', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'samba-vfs-modules', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'smbclient', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'winbind', 'pkgver': '2:4.3.11+dfsg-0ubuntu0.16.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-smbpass / libpam-winbind / etc');
}
