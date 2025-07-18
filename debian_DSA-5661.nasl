#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5661. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-3823",
    "CVE-2023-3824",
    "CVE-2024-2756",
    "CVE-2024-3096"
  );
  script_xref(name:"IAVA", value:"2024-A-0244-S");

  script_name(english:"Debian dsa-5661 : libapache2-mod-php8.2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5661 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5661-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    April 15, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : php8.2
    CVE ID         : CVE-2023-3823 CVE-2023-3824 CVE-2024-2756 CVE-2024-3096

    Multiple security issues were found in PHP, a widely-used open source
    general purpose scripting language which could result in secure cookie
    bypass, XXE attacks or incorrect validation of password hashes.

    For the stable distribution (bookworm), these problems have been fixed in
    version 8.2.18-1~deb12u1.

    We recommend that you upgrade your php8.2 packages.

    For the detailed security status of php8.2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/php8.2

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmYdfYMACgkQEMKTtsN8
    TjbrZxAAotqJ1fIulmY7fP/Ll2Gb/aoswnUqZTNiZH/yrzwX86cggI61EaWXc/JW
    7O5i7+U4y63ZIl5M6HVFk5bNgnj6Rwl5bT+jz8dbqLKkphIkT0754h1bdXCaW73r
    iiNztNclAITPYMOntY7TEWZuqS2p4cNjUuHYoPiqCLU8ASMoi/z2DHFWBc6uBLRR
    RqbhbdFbWeekzc6nt+JZmEVD9JLXsh8kO4/f5o1pbCx6pYerWM1Win5AW6ZBSNMd
    5xO5DTP3F/RX7BEyH7rTQ0y2TRCY4qk2LKG4cojqidgHIpCiTiFiKvk9W3EJZdKe
    brzHyBgEixzCImvYze68j0M0ruxWiTTozKEn9Tj7DSPNoD+vB6U8kGAqmG3b5q+p
    w9BSCQ+AZ25HvDqdasH8gaj8Ji4xAhWxVutQRrSbhcf3xKu8Y6taz3ANIRXBmgjE
    ARhK9p4b66KauAxG5GavWQQQprcbzt0deGUK6WkxigQ04l38kIrD9XIXnMHBEH4/
    Aas8E6zv8+j+18RdPaSGDGTAvuJD/C9GQjWfIvRXYVjUKarlWgtrgDoxGIMlOIHh
    RwgyJdZzJAx2vAY2o1CYmtIS59zReqwK+rAtogFi2RIoruVPGLccgxcqJOtvJF7M
    XGBAVp+3Wi4SFK5QHu1ISlngw+LkNJdkz1yXcUVI6vLt0QQEt94=
    =xxUv
    -----END PGP SIGNATURE-----

    Reply to:
    debian-security-announce@lists.debian.org
    Moritz Muehlenhoff (on-list)
    Moritz Muehlenhoff (off-list)

    Prev by Date:
    [SECURITY] [DSA 5660-1] php7.4 security update

    Next by Date:
    [SECURITY] [DSA 5662-1] apache2 security update

    Previous by thread:
    [SECURITY] [DSA 5660-1] php7.4 security update

    Next by thread:
    [SECURITY] [DSA 5662-1] apache2 security update

    Index(es):

    Date
    Thread

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php8.2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3823");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3096");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/php8.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapache2-mod-php8.2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3824");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp8.2-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libapache2-mod-php8.2', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libphp8.2-embed', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-bcmath', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-bz2', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-cgi', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-cli', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-common', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-curl', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-dba', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-dev', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-enchant', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-fpm', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-gd', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-gmp', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-imap', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-interbase', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-intl', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-ldap', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-mbstring', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-mysql', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-odbc', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-opcache', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-pgsql', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-phpdbg', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-pspell', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-readline', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-snmp', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-soap', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-sqlite3', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-sybase', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-tidy', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-xml', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-xsl', 'reference': '8.2.18-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-zip', 'reference': '8.2.18-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php8.2 / libphp8.2-embed / php8.2 / php8.2-bcmath / etc');
}
