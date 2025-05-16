#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5647. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192522);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2022-3437",
    "CVE-2023-4091",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );
  script_xref(name:"IAVA", value:"2022-A-0447-S");
  script_xref(name:"IAVA", value:"2023-A-0376-S");
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"Debian dsa-5647 : ctdb - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5647 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5647-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    March 24, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : samba
    CVE ID         : CVE-2022-2127 CVE-2022-3437 CVE-2023-4091 CVE-2023-34966
                     CVE-2023-34967 CVE-2023-34968

    Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
    print, and login server for Unix, which might result in denial of service
    or information disclosure.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 2:4.13.13+dfsg-1~deb11u6.

    We recommend that you upgrade your samba packages.

    For the detailed security status of samba please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/samba

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmYAipIACgkQEMKTtsN8
    TjZGmg//cF9sreV4nxOrR4r7HU8pfvMNlIJVyVdAYKaoLVZjZim3Fgb7/7wMZbL5
    fHDg1KJ9geMUoVJyIRkm+v3IxjTcdFPSl5OY8uRpFFQU7wtzvLvH+qc+50YKUwKv
    Ur/mCQAffDO33RVHAQbWBKwdsSqyALT33zojGXM8srV+SGp/4KiNV0CL/uo38ACZ
    lNRMpf0mXkbuaZbIQ7vlKytr9OnFXjKw8OjKM65EQ0vZ7durxiBxYzJ+wolGl2it
    yIZEJF9X6X3oefZVPdgTEYYTntPWYsW0doQlrlRFuhNB+J3Lbxd2MobSVH5BRYQO
    G15tZWd3v0NkeSmptOtTcd5HavBrY/S744J5WPvF4W6YCQaTo7LxZNa2TyMDRLL4
    gtHPSZ3HXUAIFb08gB3dO75Gymm+PKdRIfXpt4ZMldQpgql730y7GDP3eultnrU3
    N157iY3ejDNK439v7WTHI1oW6HjyyPT6OScp2uHOk7IJAVCM1UMPxRqtklNc5I6k
    qnWUmDG0v4EeYeVVxh4kTwA2XxuNNABgts7DShgXj3EwEySSx43+YGLJKSmNOrwn
    XZXr3XFZI0vbARNRczEFTay/ltZA2zrop97vYg5oQkUaXS9w7pBmwTVwK8MnctXH
    ydMG+VSUMCSCai/A78wlVPPhCytB4lLaBUdST+uVhQ01HXyWdAo=
    =0hpr
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34968");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4091");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/samba");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ctdb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ctdb', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libnss-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libpam-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libsmbclient', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libsmbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libwbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'libwbclient0', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'python3-samba', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'registry-tools', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-common', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-common-bin', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-dev', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-dsdb-modules', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-libs', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-testsuite', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'samba-vfs-modules', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'smbclient', 'reference': '2:4.13.13+dfsg-1~deb11u6'},
    {'release': '11.0', 'prefix': 'winbind', 'reference': '2:4.13.13+dfsg-1~deb11u6'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
