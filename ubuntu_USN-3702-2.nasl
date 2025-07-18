#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3702-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110940);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2018-12882");
  script_xref(name:"USN", value:"3702-2");

  script_name(english:"Ubuntu 18.04 LTS : PHP vulnerability (USN-3702-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-3702-2 advisory.

    USN-3702-1 fixed a vulnerability in PHP. PHP 7.2.7 did not actually include the fix for CVE-2018-12882.
    This update adds a backported patch to correct the issue.

    We apologize for the inconvenience.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3702-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.2-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libapache2-mod-php7.2', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libphp7.2-embed', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-bcmath', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-bz2', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-cgi', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-cli', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-common', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-curl', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-dba', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-dev', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-enchant', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-fpm', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-gd', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-gmp', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-imap', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-interbase', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-intl', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-json', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-ldap', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-mbstring', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-mysql', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-odbc', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-opcache', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-pgsql', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-phpdbg', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-pspell', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-readline', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-recode', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-snmp', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-soap', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-sqlite3', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-sybase', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-tidy', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-xml', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-xmlrpc', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-xsl', 'pkgver': '7.2.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'php7.2-zip', 'pkgver': '7.2.7-0ubuntu0.18.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.2 / libphp7.2-embed / php7.2 / php7.2-bcmath / etc');
}
