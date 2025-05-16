#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7049-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216846);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-8925", "CVE-2024-8927");
  script_xref(name:"IAVA", value:"2024-A-0609-S");
  script_xref(name:"USN", value:"7049-3");

  script_name(english:"Ubuntu 14.04 LTS : PHP vulnerabilities (USN-7049-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-7049-3 advisory.

    USN-7049-1 fixed vulnerabilities in PHP. This update provides the corresponding updates for Ubuntu 14.04
    LTS.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7049-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp5-embed");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libapache2-mod-php5', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-php5filter', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libphp5-embed', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php-pear', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-cgi', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-cli', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-common', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-curl', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-dev', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-enchant', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-fpm', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-gd', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-gmp', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-intl', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-ldap', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-mysql', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-mysqlnd', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-odbc', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-pgsql', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-pspell', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-readline', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-recode', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-snmp', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-sqlite', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-sybase', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-tidy', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-xmlrpc', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'php5-xsl', 'pkgver': '5.5.9+dfsg-1ubuntu4.29+esm16', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php5 / libapache2-mod-php5filter / libphp5-embed / etc');
}
