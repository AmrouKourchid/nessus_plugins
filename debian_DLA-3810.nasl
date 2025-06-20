#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3810. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(195146);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-31629", "CVE-2024-2756", "CVE-2024-3096");

  script_name(english:"Debian dla-3810 : libapache2-mod-php7.3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3810 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3810-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    May 07, 2024                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : php7.3
    Version        : 7.3.31-1~deb10u6
    CVE ID         : CVE-2024-2756 CVE-2024-3096

    Security issues were found in PHP, a widely-used open source general
    purpose scripting language, which could result in information disclosure
    or incorrect validation of password hashes.

    CVE-2024-2756

        Marco Squarcina discovered that network and same-site attackers can
        set a standard insecure cookie in the victim's browser which is
        treated as a `__Host-` or `__Secure-` cookie by PHP applications.

        This issue stems from an incomplete fix to CVE-2022-31629.

    CVE-2024-3096

        Eric Stern discovered that if a password stored with password_hash()
        starts with a null byte (\x00), testing a blank string as the
        password via password_verify() incorrectly returns true.

        If a user were able to create a password with a leading null byte
        (unlikely, but syntactically valid), the issue would allow an
        attacker to trivially compromise the victim's account by attempting
        to sign in with a blank string.

    For Debian 10 buster, these problems have been fixed in version
    7.3.31-1~deb10u6.

    We recommend that you upgrade your php7.3 packages.

    For the detailed security status of php7.3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/php7.3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3096");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/php7.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapache2-mod-php7.3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp7.3-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libapache2-mod-php7.3', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'libphp7.3-embed', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-bcmath', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-bz2', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-cgi', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-cli', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-common', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-curl', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-dba', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-dev', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-enchant', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-fpm', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-gd', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-gmp', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-imap', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-interbase', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-intl', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-json', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-ldap', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-mbstring', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-mysql', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-odbc', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-opcache', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-pgsql', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-phpdbg', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-pspell', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-readline', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-recode', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-snmp', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-soap', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-sqlite3', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-sybase', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-tidy', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-xml', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-xmlrpc', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-xsl', 'reference': '7.3.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'php7.3-zip', 'reference': '7.3.31-1~deb10u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.3 / libphp7.3-embed / php7.3 / php7.3-bcmath / etc');
}
