##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4639-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143119);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2018-7260",
    "CVE-2018-19968",
    "CVE-2018-19970",
    "CVE-2019-6798",
    "CVE-2019-6799",
    "CVE-2019-11768",
    "CVE-2019-12616",
    "CVE-2019-19617",
    "CVE-2020-5504",
    "CVE-2020-10802",
    "CVE-2020-10803",
    "CVE-2020-10804",
    "CVE-2020-26934",
    "CVE-2020-26935"
  );
  script_bugtraq_id(
    103099,
    106178,
    106181,
    106727,
    106736,
    108617,
    108619
  );
  script_xref(name:"USN", value:"4639-1");

  script_name(english:"Ubuntu 18.04 LTS : phpMyAdmin vulnerabilities (USN-4639-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4639-1 advisory.

    It was discovered that there was a bug in the way phpMyAdmin handles the phpMyAdmin Configuration Storage
    tables. An authenticated attacker could use this vulnerability to cause phpmyAdmin to leak sensitive
    files. (CVE-2018-19968)

    It was discovered that phpMyAdmin incorrectly handled user input. An attacker could possibly use this for
    an XSS attack. (CVE-2018-19970)

    It was discovered that phpMyAdmin mishandled certain input. An attacker could use this vulnerability to
    execute a cross-site scripting (XSS) attack via a crafted URL. (CVE-2018-7260)

    It was discovered that phpMyAdmin failed to sanitize certain input. An attacker could use this
    vulnerability to execute an SQL injection attack via a specially crafted database name. (CVE-2019-11768)

    It was discovered that phpmyadmin incorrectly handled some requests. An attacker could possibly use this
    to perform a CSRF attack. (CVE-2019-12616)

    It was discovered that phpMyAdmin failed to sanitize certain input. An attacker could use this
    vulnerability to execute an SQL injection attack via a specially crafted username. (CVE-2019-6798,
    CVE-2020-10804, CVE-2020-5504)

    It was discovered that phpMyAdmin would allow sensitive files to be leaked if certain configuration
    options were set. An attacker could use this vulnerability to access confidential information.
    (CVE-2019-6799)

    It was discovered that phpMyAdmin failed to sanitize certain input. An attacker could use this
    vulnerability to execute an SQL injection attack via a specially crafted database or table name.
    (CVE-2020-10802)

    It was discovered that phpMyAdmin did not properly handle data from the database when displaying it. If an
    attacker were to insert specially- crafted data into certain database tables, the attacker could execute a
    cross-site scripting (XSS) attack. (CVE-2020-10803)

    It was discovered that phpMyAdmin was vulnerable to an XSS attack. If a victim were to click on a crafted
    link, an attacker could run malicious JavaScript on the victim's system. (CVE-2020-26934)

    It was discovered that phpMyAdmin did not properly handler certain SQL statements in the search feature.
    An attacker could use this vulnerability to inject malicious SQL into a query. (CVE-2020-26935)

    It was discovered that phpMyAdmin did not properly sanitize certain input. An attacker could use this
    vulnerability to possibly execute an HTML injection or a cross-site scripting (XSS) attack.
    (CVE-2019-19617)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4639-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected phpmyadmin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phpmyadmin");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'phpmyadmin', 'pkgver': '4:4.6.6-5ubuntu0.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'phpmyadmin');
}
