##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4583-2. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141936);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2020-7069", "CVE-2020-7070");
  script_xref(name:"USN", value:"4583-2");

  script_name(english:"Ubuntu 20.10 : PHP vulnerabilities (USN-4583-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-4583-2 advisory.

    Several security issues were fixed in PHP.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4583-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7069");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.4-embed");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('20.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.10', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-common', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-json', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.9-1ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.9-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.4 / libphp7.4-embed / php7.4 / php7.4-bcmath / etc');
}
