#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4432-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139365);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");
  script_xref(name:"USN", value:"4432-2");
  script_xref(name:"IAVA", value:"2020-A-0349");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : GRUB2 regression (USN-4432-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-4432-2 advisory.

    USN-4432-1 fixed vulnerabilities in GRUB2 affecting Secure Boot environments. Unfortunately, the update
    introduced regressions for some BIOS systems (either pre-UEFI or UEFI configured in Legacy mode),
    preventing them from successfully booting. This update addresses the issue.

    Users with BIOS systems that installed GRUB2 versions from USN-4432-1 should verify that their GRUB2
    installation has a correct understanding of their boot device location and installed the boot loader
    correctly.

    We apologize for the inconvenience.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4432-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-ia32-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-firmware-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-ieee1275");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-ieee1275-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-linuxbios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-mount-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-pc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-rescue-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-theme-starfield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-uboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-uboot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-xen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-xen-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-coreboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-coreboot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'grub-common', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-coreboot', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-coreboot-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.66.27+2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-arm', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-arm-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.66.27+2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-ia32', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-efi-ia32-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-emu', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-firmware-qemu', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-ieee1275', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-ieee1275-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-linuxbios', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-mount-udeb', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-pc', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-pc-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-rescue-pc', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-theme-starfield', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-uboot', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-uboot-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-xen', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-xen-bin', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub-xen-host', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub2', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '16.04', 'pkgname': 'grub2-common', 'pkgver': '2.02~beta2-36ubuntu3.27'},
    {'osver': '18.04', 'pkgname': 'grub-common', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-coreboot', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-coreboot-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.93.19+2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.93.19+2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-ia32', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-efi-ia32-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-emu', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-firmware-qemu', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-ieee1275', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-ieee1275-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-linuxbios', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-mount-udeb', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-pc', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-pc-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-rescue-pc', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-theme-starfield', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-uboot', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-uboot-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-xen', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-xen-bin', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub-xen-host', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub2', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '18.04', 'pkgname': 'grub2-common', 'pkgver': '2.02-2ubuntu8.17'},
    {'osver': '20.04', 'pkgname': 'grub-common', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-coreboot', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-coreboot-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.142.4+2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed-template', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.142.4+2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed-template', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-ia32', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-ia32-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-emu', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-firmware-qemu', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-ieee1275', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-ieee1275-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-linuxbios', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-mount-udeb', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-pc', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-pc-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-rescue-pc', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-theme-starfield', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-uboot', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-uboot-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-xen', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-xen-bin', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub-xen-host', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub2', 'pkgver': '2.04-1ubuntu26.2'},
    {'osver': '20.04', 'pkgname': 'grub2-common', 'pkgver': '2.04-1ubuntu26.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub-common / grub-coreboot / grub-coreboot-bin / grub-efi / etc');
}
