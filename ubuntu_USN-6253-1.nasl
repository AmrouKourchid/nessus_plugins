#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6253-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178915);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-3750");
  script_xref(name:"USN", value:"6253-1");

  script_name(english:"Ubuntu 23.04 : libvirt vulnerability (USN-6253-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 23.04 host has packages installed that are affected by a vulnerability as referenced in the USN-6253-1
advisory.

    It wad discovered that libvirt incorrectly handled locking when processing certain requests. A local
    attacker could possibly use this issue to cause libvirt to stop responding or crash, resulting in a denial
    of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6253-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
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
if (! ('23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '23.04', 'pkgname': 'libnss-libvirt', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-clients', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-clients-qemu', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-config-network', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-config-nwfilter', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-lxc', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-qemu', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-storage-iscsi-direct', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-vbox', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-driver-xen', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-system-systemd', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-daemon-system-sysv', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-dev', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-l10n', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-login-shell', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '9.0.0-2ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'libvirt0', 'pkgver': '9.0.0-2ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-libvirt / libvirt-clients / libvirt-clients-qemu / etc');
}
