#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3095-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93864);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7133",
    "CVE-2016-7134",
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418"
  );
  script_xref(name:"USN", value:"3095-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : PHP vulnerabilities (USN-3095-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3095-1 advisory.

    Taoguang Chen discovered that PHP incorrectly handled certain invalid objects when unserializing data. A
    remote attacker could use this issue to cause PHP to crash, resulting in a denial of service, or possibly
    execute arbitrary code. (CVE-2016-7124)

    Taoguang Chen discovered that PHP incorrectly handled invalid session names. A remote attacker could use
    this issue to inject arbitrary session data. (CVE-2016-7125)

    It was discovered that PHP incorrectly handled certain gamma values in the imagegammacorrect function. A
    remote attacker could use this issue to cause PHP to crash, resulting in a denial of service, or possibly
    execute arbitrary code. (CVE-2016-7127)

    It was discovered that PHP incorrectly handled certain crafted TIFF image thumbnails. A remote attacker
    could use this issue to cause PHP to crash, resulting in a denial of service, or possibly expose sensitive
    information. (CVE-2016-7128)

    It was discovered that PHP incorrectly handled unserializing certain wddxPacket XML documents. A remote
    attacker could use this issue to cause PHP to crash, resulting in a denial of service, or possibly execute
    arbitrary code. (CVE-2016-7129, CVE-2016-7130, CVE-2016-7131, CVE-2016-7132, CVE-2016-7413)

    It was discovered that PHP incorrectly handled certain memory operations. A remote attacker could use this
    issue to cause PHP to crash, resulting in a denial of service, or possibly execute arbitrary code. This
    issue only affected Ubuntu 16.04 LTS. (CVE-2016-7133)

    It was discovered that PHP incorrectly handled long strings in curl_escape calls. A remote attacker could
    use this issue to cause PHP to crash, resulting in a denial of service, or possibly execute arbitrary
    code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-7134)

    Taoguang Chen discovered that PHP incorrectly handled certain failures when unserializing data. A remote
    attacker could use this issue to cause PHP to crash, resulting in a denial of service, or possibly execute
    arbitrary code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-7411)

    It was discovered that PHP incorrectly handled certain flags in the MySQL driver. Malicious remote MySQL
    servers could use this issue to cause PHP to crash, resulting in a denial of service, or possibly execute
    arbitrary code. (CVE-2016-7412)

    It was discovered that PHP incorrectly handled ZIP file signature verification when processing a PHAR
    archive. A remote attacker could use this issue to cause PHP to crash, resulting in a denial of service,
    or possibly execute arbitrary code. (CVE-2016-7414)

    It was discovered that PHP incorrectly handled certain locale operations. A remote attacker could use this
    issue to cause PHP to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2016-7416)

    It was discovered that PHP incorrectly handled SplArray unserializing. A remote attacker could use this
    issue to cause PHP to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2016-7417)

    Ke Liu discovered that PHP incorrectly handled unserializing wddxPacket XML documents with incorrect
    boolean elements. A remote attacker could use this issue to cause PHP to crash, resulting in a denial of
    service, or possibly execute arbitrary code. (CVE-2016-7418)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3095-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7417");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp5-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libapache2-mod-php5', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-php5filter', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'libphp5-embed', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php-pear', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-cgi', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-cli', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-common', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-curl', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-dev', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-enchant', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-fpm', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-gd', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-gmp', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-intl', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-ldap', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-mysql', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-mysqlnd', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-odbc', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-pgsql', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-pspell', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-readline', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-recode', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-snmp', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-sqlite', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-sybase', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-tidy', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-xmlrpc', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'php5-xsl', 'pkgver': '5.5.9+dfsg-1ubuntu4.20'},
    {'osver': '16.04', 'pkgname': 'libapache2-mod-php7.0', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libphp7.0-embed', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-bcmath', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-bz2', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-cgi', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-cli', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-common', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-curl', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-dba', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-dev', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-enchant', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-fpm', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-gd', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-gmp', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-imap', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-interbase', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-intl', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-json', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-ldap', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-mbstring', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-mcrypt', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-mysql', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-odbc', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-opcache', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-pgsql', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-phpdbg', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-pspell', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-readline', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-recode', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-snmp', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-soap', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-sqlite3', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-sybase', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-tidy', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-xml', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-xmlrpc', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-xsl', 'pkgver': '7.0.8-0ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'php7.0-zip', 'pkgver': '7.0.8-0ubuntu0.16.04.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php5 / libapache2-mod-php5filter / etc');
}
