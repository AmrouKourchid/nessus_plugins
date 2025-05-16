#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6638-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190562);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2022-36763",
    "CVE-2022-36764",
    "CVE-2022-36765",
    "CVE-2023-45230",
    "CVE-2023-45231",
    "CVE-2023-45232",
    "CVE-2023-45233",
    "CVE-2023-45234",
    "CVE-2023-45235",
    "CVE-2023-48733"
  );
  script_xref(name:"USN", value:"6638-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 : EDK II vulnerabilities (USN-6638-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6638-1 advisory.

    Marc Beatove discovered buffer overflows exit in EDK2. An attacker on the local network could potentially
    use this to impact availability or possibly cause remote code execution. (CVE-2022-36763, CVE-2022-36764,
    CVE-2022-36765)

    It was discovered that a buffer overflows exists in EDK2's Network Package An attacker on the local
    network could potentially use these to impact availability or possibly cause remote code execution.
    (CVE-2023-45230, CVE-2023-45234, CVE-2023-45235)

    It was discovered that an out-of-bounds read exists in EDK2's Network Package An attacker on the local
    network could potentially use this to impact confidentiality. (CVE-2023-45231)

    It was discovered that infinite-loops exists in EDK2's Network Package An attacker on the local network
    could potentially use these to impact availability. (CVE-2023-45232, CVE-2023-45233)

    Mate Kukri discovered that an insecure default to allow UEFI Shell in EDK2 was left enabled in Ubuntu's
    EDK2. An attacker could use this to bypass Secure Boot. (CVE-2023-48733)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6638-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:efi-shell-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:efi-shell-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:efi-shell-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:efi-shell-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovmf-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi-arm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ovmf', 'pkgver': '0~20191122.bd85bf54-2ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'qemu-efi', 'pkgver': '0~20191122.bd85bf54-2ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'qemu-efi-aarch64', 'pkgver': '0~20191122.bd85bf54-2ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'qemu-efi-arm', 'pkgver': '0~20191122.bd85bf54-2ubuntu3.5'},
    {'osver': '22.04', 'pkgname': 'ovmf', 'pkgver': '2022.02-3ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'ovmf-ia32', 'pkgver': '2022.02-3ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'qemu-efi', 'pkgver': '2022.02-3ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'qemu-efi-aarch64', 'pkgver': '2022.02-3ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'qemu-efi-arm', 'pkgver': '2022.02-3ubuntu0.22.04.2'},
    {'osver': '23.10', 'pkgname': 'efi-shell-aa64', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'efi-shell-arm', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'efi-shell-ia32', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'efi-shell-x64', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'ovmf', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'ovmf-ia32', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'qemu-efi-aarch64', 'pkgver': '2023.05-2ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'qemu-efi-arm', 'pkgver': '2023.05-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'efi-shell-aa64 / efi-shell-arm / efi-shell-ia32 / efi-shell-x64 / etc');
}
