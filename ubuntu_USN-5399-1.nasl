##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5399-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160444);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-25637",
    "CVE-2021-3631",
    "CVE-2021-3667",
    "CVE-2021-3975",
    "CVE-2021-4147",
    "CVE-2022-0897"
  );
  script_xref(name:"USN", value:"5399-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : libvirt vulnerabilities (USN-5399-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5399-1 advisory.

    It was discovered that libvirt incorrectly handled certain locking operations. A local attacker could
    possibly use this issue to cause libvirt to stop accepting connections, resulting in a denial of service.
    This issue only affected Ubuntu 20.04 LTS. (CVE-2021-3667)

    It was discovered that libvirt incorrectly handled threads during shutdown. A local attacker could
    possibly use this issue to cause libvirt to crash, resulting in a denial of service. This issue only
    affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-3975)

    It was discovered that libvirt incorrectly handled the libxl driver. An attacker inside a guest could
    possibly use this issue to cause libvirtd to crash or stop responding, resulting in a denial of service.
    This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.10. (CVE-2021-4147)

    It was discovered that libvirt incorrectly handled the nwfilter driver. A local attacker could possibly
    use this issue to cause libvirt to crash, resulting in a denial of service. (CVE-2022-0897)

    It was discovered that libvirt incorrectly handled the polkit access control driver. A local attacker
    could possibly use this issue to cause libvirt to crash, resulting in a denial of service. This issue only
    affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-25637)

    It was discovered that libvirt incorrectly generated SELinux labels. In environments using SELinux, this
    issue could allow the sVirt confinement to be bypassed. This issue only affected Ubuntu 18.04 LTS and
    Ubuntu 20.04 LTS. (CVE-2021-3631)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5399-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-sheepdog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libnss-libvirt', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-bin', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-clients', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-sheepdog', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-dev', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt0', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '20.04', 'pkgname': 'libnss-libvirt', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-clients', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-lxc', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-qemu', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-vbox', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-xen', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system-systemd', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system-sysv', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-dev', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt0', 'pkgver': '6.0.0-0ubuntu8.16'}
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
