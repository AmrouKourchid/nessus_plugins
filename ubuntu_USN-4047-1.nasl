#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4047-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126563);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-10161",
    "CVE-2019-10166",
    "CVE-2019-10167",
    "CVE-2019-10168"
  );
  script_xref(name:"USN", value:"4047-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : libvirt vulnerabilities (USN-4047-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4047-1 advisory.

    Matthias Gerstner and Jn Tomko discovered that libvirt incorrectly handled certain API calls. An
    attacker could possibly use this issue to check for arbitrary files, or execute arbitrary binaries. In the
    default installation, attackers would be isolated by the libvirt AppArmor profile.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4047-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10161");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-sheepdog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-libvirt");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libvirt-bin', 'pkgver': '1.3.1-1ubuntu10.27'},
    {'osver': '16.04', 'pkgname': 'libvirt-dev', 'pkgver': '1.3.1-1ubuntu10.27'},
    {'osver': '16.04', 'pkgname': 'libvirt0', 'pkgver': '1.3.1-1ubuntu10.27'},
    {'osver': '18.04', 'pkgname': 'libnss-libvirt', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-bin', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-clients', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-sheepdog', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-dev', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '4.0.0-1ubuntu8.12'},
    {'osver': '18.04', 'pkgname': 'libvirt0', 'pkgver': '4.0.0-1ubuntu8.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-libvirt / libvirt-bin / libvirt-clients / libvirt-daemon / etc');
}
