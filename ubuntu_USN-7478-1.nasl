#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7478-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235146);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id("CVE-2025-30472");
  script_xref(name:"USN", value:"7478-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : Corosync vulnerability (USN-7478-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-7478-1 advisory.

    It was discovered that Corosync incorrectly handled certain large UDP packets. If encryption is disabled,
    or an attacker knows the encryption key, this issue could be used to cause Corosync to crash, resulting in
    a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7478-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:corosync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:corosync-notifyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:corosync-vqsim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcfg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcfg7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcmap4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcorosync-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcorosync-common4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcpg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libquorum-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libquorum5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsam-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsam4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvotequorum-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvotequorum8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'corosync', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'corosync-notifyd', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'corosync-vqsim', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcfg-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcfg7', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcmap-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcmap4', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcorosync-common-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcorosync-common4', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcpg-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libcpg4', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libquorum-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libquorum5', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libsam-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libsam4', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libvotequorum-dev', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'libvotequorum8', 'pkgver': '3.0.3-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'corosync', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'corosync-notifyd', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'corosync-vqsim', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcfg-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcfg7', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcmap-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcmap4', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcorosync-common-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcorosync-common4', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcpg-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcpg4', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libquorum-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libquorum5', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsam-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libsam4', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libvotequorum-dev', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libvotequorum8', 'pkgver': '3.1.6-1ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'corosync', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'corosync-notifyd', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'corosync-vqsim', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcfg-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcfg7', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcmap-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcmap4', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcorosync-common-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcorosync-common4', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcpg-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libcpg4', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libquorum-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libquorum5', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libsam-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libsam4', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libvotequorum-dev', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.04', 'pkgname': 'libvotequorum8', 'pkgver': '3.1.7-1ubuntu3.1'},
    {'osver': '24.10', 'pkgname': 'corosync', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'corosync-notifyd', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'corosync-vqsim', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcfg-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcfg7', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcmap-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcmap4', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcorosync-common-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcorosync-common4', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcpg-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libcpg4', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libquorum-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libquorum5', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libsam-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libsam4', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libvotequorum-dev', 'pkgver': '3.1.8-2ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libvotequorum8', 'pkgver': '3.1.8-2ubuntu1.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'corosync / corosync-notifyd / corosync-vqsim / libcfg-dev / libcfg7 / etc');
}
