#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6355-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181178);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-3695",
    "CVE-2021-3696",
    "CVE-2021-3697",
    "CVE-2021-3981",
    "CVE-2022-3775",
    "CVE-2022-28733",
    "CVE-2022-28734",
    "CVE-2022-28735",
    "CVE-2022-28736",
    "CVE-2022-28737"
  );
  script_xref(name:"USN", value:"6355-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : GRUB2 vulnerabilities (USN-6355-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6355-1 advisory.

    Daniel Axtens discovered that specially crafted images could cause a heap-based out-of-bonds write. A
    local attacker could possibly use this to circumvent secure boot protections. (CVE-2021-3695)

    Daniel Axtens discovered that specially crafted images could cause out-of-bonds read and write. A local
    attacker could possibly use this to circumvent secure boot protections. (CVE-2021-3696)

    Daniel Axtens discovered that specially crafted images could cause buffer underwrite which allows
    arbitrary data to be written to a heap. A local attacker could possibly use this to circumvent secure boot
    protections. (CVE-2021-3697)

    It was discovered that GRUB2 configuration files were created with the wrong permissions. An attacker
    could possibly use this to leak encrypted passwords. (CVE-2021-3981)

    Daniel Axtens discovered that specially crafted IP packets could cause an integer underflow and write past
    the end of a buffer. An attacker could possibly use this to circumvent secure boot protections.
    (CVE-2022-28733)

    Daniel Axtens discovered that specially crafted HTTP headers can cause an out-of-bounds write of a NULL
    byte. An attacker could possibly use this to corrupt GRUB2's internal data. (CVE-2022-28734)

    Julian Andres Klode discovered that GRUB2 shim_lock allowed non- kernel files to be loaded. A local attack
    could possibly use this to circumvent secure boot protections. (CVE-2022-28735)

    Chris Coulson discovered that executing chainloaders more than once caused a use-after-free vulnerability.
    A local attack could possibly use this to circumvent secure boot protections. (CVE-2022-28736)

    Chris Coulson discovered that specially crafted executables could cause shim to make out-of-bound writes.
    A local attack could possibly use this to circumvent secure boot protections. (CVE-2022-28737)

    Zhang Boyang discovered that specially crafted unicode sequences could lead to an out-of-bounds write to a
    heap. A local attacker could possibly use this to circumvent secure boot protections. (CVE-2022-3775)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6355-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:shim-signed");
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
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.187.3~20.04.1+2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.187.3~20.04.1+2.06-2ubuntu14.1'},
    {'osver': '20.04', 'pkgname': 'shim', 'pkgver': '15.7-0ubuntu1'},
    {'osver': '20.04', 'pkgname': 'shim-signed', 'pkgver': '1.40.9+15.7-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.187.3~22.04.1+2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.187.3~22.04.1+2.06-2ubuntu14.1'},
    {'osver': '22.04', 'pkgname': 'shim', 'pkgver': '15.7-0ubuntu1'},
    {'osver': '22.04', 'pkgname': 'shim-signed', 'pkgver': '1.51.3+15.7-0ubuntu1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub-efi-amd64 / grub-efi-amd64-bin / grub-efi-amd64-signed / etc');
}
