#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4992-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150867);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-14372",
    "CVE-2020-25632",
    "CVE-2020-27749",
    "CVE-2020-27779",
    "CVE-2021-20225",
    "CVE-2021-20233"
  );
  script_xref(name:"USN", value:"4992-1");
  script_xref(name:"IAVA", value:"2020-A-0349");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : GRUB 2 vulnerabilities (USN-4992-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4992-1 advisory.

    Mt Kukri discovered that the acpi command in GRUB 2 allowed privileged users to load crafted ACPI
    tables when secure boot is enabled. An attacker could use this to bypass UEFI Secure Boot restrictions.
    (CVE-2020-14372)

    Chris Coulson discovered that the rmmod command in GRUB 2 contained a use- after-free vulnerability. A
    local attacker could use this to execute arbitrary code and bypass UEFI Secure Boot restrictions.
    (CVE-2020-25632)

    Chris Coulson discovered that a buffer overflow existed in the command line parser in GRUB 2. A local
    attacker could use this to execute arbitrary code and bypass UEFI Secure Boot restrictions.
    (CVE-2020-27749)

    It was discovered that the cutmem command in GRUB 2 did not honor secure boot locking. A local attacker
    could use this to execute arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2020-27779)

    It was discovered that the option parser in GRUB 2 contained a heap overflow vulnerability. A local
    attacker could use this to execute arbitrary code and bypass UEFI Secure Boot restrictions.
    (CVE-2021-20225)

    It was discovered that the menu rendering implementation in GRUB 2 did not properly calculate the amount
    of memory needed in some situations, leading to out-of-bounds writes. A local attacker could use this to
    execute arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2021-20233)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4992-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.167~18.04.5+2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.167~18.04.5+2.04-1ubuntu44.1.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.167.2+2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.167.2+2.04-1ubuntu44.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub-efi-amd64 / grub-efi-amd64-bin / grub-efi-amd64-signed / etc');
}
