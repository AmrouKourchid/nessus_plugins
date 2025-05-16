#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5624. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(190574);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2022-36763",
    "CVE-2022-36764",
    "CVE-2022-36765",
    "CVE-2023-45229",
    "CVE-2023-45230",
    "CVE-2023-45231",
    "CVE-2023-45232",
    "CVE-2023-45233",
    "CVE-2023-45234",
    "CVE-2023-45235",
    "CVE-2023-48733"
  );

  script_name(english:"Debian dsa-5624 : ovmf - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5624 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5624-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    February 14, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : edk2
    CVE ID         : CVE-2023-48733

    Mate Kukri discovered the Debian build of EDK2, a UEFI firmware
    implementation, used an insecure default configuration which could result
    in Secure Boot bypass via the UEFI shell.

    This updates disables the UEFI shell if Secure Boot is used.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 2020.11-2+deb11u2.

    For the stable distribution (bookworm), this problem has been fixed in
    version 2022.11-6+deb12u1. This update also addresses several security
    issues in the ipv6 network stack (CVE-2022-36763, CVE-2022-36764,
    CVE-2022-36765, CVE-2023-45230, CVE-2023-45229, CVE-2023-45231,
    CVE-2023-45232, CVE-2023-45233, CVE-2023-45234, CVE-2023-45235)

    We recommend that you upgrade your edk2 packages.

    For the detailed security status of edk2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/edk2

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmXNGWIACgkQEMKTtsN8
    TjaBVg/8D3psWKk7kf9Ht+2Bbfsp5cN63qKRPAXTDjGELCp+98Dd7CUaZnCCxA4w
    W0xAqWdHWkx+PbgyLJ3aPzttL//yk3ZIBEXl6pw/o2jicFlf7ds1zlJFZJbfl63h
    Vb9cJCjrgnPgH6SLfQeHckad5876LE78xl5mukRyL3ZWeSHOBRavFvct14H2qDAM
    quXtQKHtw6NOVc3ZciSHbBhjNG+hhPJL0eZ6HSDf2MI5ulYjMcNwgVm7jEwOGq4l
    VUowCNbJ71PzI5T26H2HqDkQTCFEEZJzjt3PDStVT7hnhVpbUqtvJxjHYruuWzPI
    FwpjIyA9LkQqP4CRVgK/6+FeuE/F28iUkrStXzPYAXPUzJ7GWSFfz16ViyuUJf6s
    pWpMhcruIwBnH1iLQt68hFodiCcJeQaim3u3cQfFsE4YvlTPzj9NddoBzXsCdG81
    EfeFH9/J1iEkKxQ76Ocw8TiLhVe2C09MVqIKCB9YDf1ESR6TaBV7Hdx0Dh7XOVc9
    +symHPmLP/0Bt7rIQXCi/aYz96qtl5/wHSWiEWRCogSUOJ05OEF+/QJqWWIrim4Z
    9RMW9BZCGJBaUi83Ye+HUdxjnZkpT5kMiEH2y7CY85R5fuBMn4GC8gf66hcxT4mi
    lzLMpt/jtdH3h0J9MKFq85TlPf9pxGAF/o3Neg5KtSmYVKqbkIs=
    =yQYY
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/edk2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45231");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45232");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-48733");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/edk2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/edk2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ovmf packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovmf-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-efi-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-efi-arm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ovmf', 'reference': '2020.11-2+deb11u2'},
    {'release': '11.0', 'prefix': 'ovmf-ia32', 'reference': '2020.11-2+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-efi', 'reference': '2020.11-2+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-efi-aarch64', 'reference': '2020.11-2+deb11u2'},
    {'release': '11.0', 'prefix': 'qemu-efi-arm', 'reference': '2020.11-2+deb11u2'},
    {'release': '12.0', 'prefix': 'ovmf', 'reference': '2022.11-6+deb12u1'},
    {'release': '12.0', 'prefix': 'ovmf-ia32', 'reference': '2022.11-6+deb12u1'},
    {'release': '12.0', 'prefix': 'qemu-efi', 'reference': '2022.11-6+deb12u1'},
    {'release': '12.0', 'prefix': 'qemu-efi-aarch64', 'reference': '2022.11-6+deb12u1'},
    {'release': '12.0', 'prefix': 'qemu-efi-arm', 'reference': '2022.11-6+deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovmf / ovmf-ia32 / qemu-efi / qemu-efi-aarch64 / qemu-efi-arm');
}
