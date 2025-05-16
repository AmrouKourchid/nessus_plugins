#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6954-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205391);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-6683", "CVE-2023-6693", "CVE-2024-24474");
  script_xref(name:"IAVB", value:"2024-B-0022-S");
  script_xref(name:"IAVB", value:"2024-B-0070-S");
  script_xref(name:"USN", value:"6954-1");

  script_name(english:"Ubuntu 22.04 LTS : QEMU vulnerabilities (USN-6954-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6954-1 advisory.

    Markus Frank and Fiona Ebner discovered that QEMU did not properly handle certain memory operations,
    leading to a NULL pointer dereference. An authenticated user could potentially use this issue to cause a
    denial of service. (CVE-2023-6683)

    Xiao Lei discovered that QEMU did not properly handle certain memory

    operations when specific features were enabled, which could lead to a stack overflow. An attacker could
    potentially use this issue to leak sensitive information. (CVE-2023-6693)

    It was discovered that QEMU had an integer underflow vulnerability in

    the TI command, which would result in a buffer overflow. An attacker could potentially use this issue to
    cause a denial of service.

    (CVE-2024-24474)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6954-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'qemu', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-user', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'},
    {'osver': '22.04', 'pkgname': 'qemu-utils', 'pkgver': '1:6.2+dfsg-2ubuntu6.22'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-system / etc');
}
