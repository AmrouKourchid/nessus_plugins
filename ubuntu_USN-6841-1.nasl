#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6841-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200740);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2024-5458");
  script_xref(name:"USN", value:"6841-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : PHP vulnerability (USN-6841-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-6841-1 advisory.

    It was discovered that PHP could early return in the filter_var function resulting in invalid user
    information being treated as valid user information. An attacker could possibly use this issue to expose
    raw user input information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6841-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5458");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.4-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp8.1-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp8.2-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp8.3-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.2-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.3-zip");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-common', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-json', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '20.04', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.3-4ubuntu2.23'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php8.0', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php8.1', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'libphp8.1-embed', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-bcmath', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-bz2', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-cgi', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-cli', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-common', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-curl', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-dba', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-dev', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-enchant', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-fpm', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-gd', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-gmp', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-imap', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-interbase', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-intl', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-ldap', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-mbstring', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-mysql', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-odbc', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-opcache', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-pgsql', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-phpdbg', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-pspell', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-readline', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-snmp', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-soap', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-sqlite3', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-sybase', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-tidy', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-xml', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-xsl', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'php8.1-zip', 'pkgver': '8.1.2-1ubuntu2.18'},
    {'osver': '23.10', 'pkgname': 'libapache2-mod-php8.2', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'libphp8.2-embed', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-bcmath', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-bz2', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-cgi', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-cli', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-common', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-curl', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-dba', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-dev', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-enchant', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-fpm', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-gd', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-gmp', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-imap', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-interbase', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-intl', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-ldap', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-mbstring', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-mysql', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-odbc', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-opcache', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-pgsql', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-phpdbg', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-pspell', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-readline', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-snmp', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-soap', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-sqlite3', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-sybase', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-tidy', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-xml', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-xsl', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '23.10', 'pkgname': 'php8.2-zip', 'pkgver': '8.2.10-2ubuntu2.2'},
    {'osver': '24.04', 'pkgname': 'libapache2-mod-php8.3', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'libphp8.3-embed', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-bcmath', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-bz2', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-cgi', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-cli', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-common', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-curl', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-dba', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-dev', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-enchant', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-fpm', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-gd', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-gmp', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-imap', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-interbase', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-intl', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-ldap', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-mbstring', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-mysql', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-odbc', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-opcache', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-pgsql', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-phpdbg', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-pspell', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-readline', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-snmp', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-soap', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-sqlite3', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-sybase', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-tidy', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-xml', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-xsl', 'pkgver': '8.3.6-0ubuntu0.24.04.1'},
    {'osver': '24.04', 'pkgname': 'php8.3-zip', 'pkgver': '8.3.6-0ubuntu0.24.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.4 / libapache2-mod-php8.0 / etc');
}
