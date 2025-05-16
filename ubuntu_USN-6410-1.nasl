#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6410-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182480);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2023-4692", "CVE-2023-4693");
  script_xref(name:"USN", value:"6410-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 : GRUB2 vulnerabilities (USN-6410-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6410-1 advisory.

    It was discovered that a specially crafted file system image could cause a heap-based out-of-bounds write.
    A local attacker could potentially use this to perform arbitrary code execution bypass and bypass secure
    boot protections. (CVE-2023-4692)

    It was discovered that a specially crafted file system image could cause an out-of-bounds read. A
    physically-present attacker could possibly use this to leak sensitive information to the GRUB pager.
    (CVE-2023-4693)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6410-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4692");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.187.6~20.04.1+2.06-2ubuntu14.4'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.187.6~20.04.1+2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.187.6+2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.06-2ubuntu14.4'},
    {'osver': '22.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.187.6+2.06-2ubuntu14.4'},
    {'osver': '23.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.06-2ubuntu17.2'},
    {'osver': '23.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.06-2ubuntu17.2'},
    {'osver': '23.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.193.2+2.06-2ubuntu17.2'},
    {'osver': '23.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.06-2ubuntu17.2'},
    {'osver': '23.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.06-2ubuntu17.2'},
    {'osver': '23.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.193.2+2.06-2ubuntu17.2'}
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
