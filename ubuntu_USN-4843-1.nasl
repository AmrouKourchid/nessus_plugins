#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4843-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183178);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-9218",
    "CVE-2016-6609",
    "CVE-2016-6619",
    "CVE-2016-6630",
    "CVE-2016-9849",
    "CVE-2016-9866",
    "CVE-2017-18264",
    "CVE-2017-1000014",
    "CVE-2017-1000015",
    "CVE-2018-7260",
    "CVE-2018-12581",
    "CVE-2018-19968",
    "CVE-2018-19970",
    "CVE-2019-6798",
    "CVE-2019-11768",
    "CVE-2019-12616",
    "CVE-2019-12922",
    "CVE-2019-19617",
    "CVE-2020-5504",
    "CVE-2020-26934",
    "CVE-2020-26935"
  );
  script_xref(name:"USN", value:"4843-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM : phpMyAdmin vulnerabilities (USN-4843-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-4843-1 advisory.

    Javier Nieto and Andres Rojas discovered that phpMyAdmin incorrectly managed input in the form of
    passwords. An attacker could use this vulnerability to cause a denial-of-service (DoS). This issue only
    affected Ubuntu 14.04 ESM. (CVE-2014-9218)

    Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize input in the form of database
    names in the PHP Array export feature. An authenticated attacker could use this vulnerability to run
    arbitrary PHP commands. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2016-6609)

    Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize input. An attacker could use
    this vulnerability to execute SQL injection attacks. This issue only affected Ubuntu 14.04 ESM and Ubuntu
    16.04 ESM. (CVE-2016-6619)

    Emanuel Bronshtein discovered that phpMyadmin failed to properly sanitize input. An authenticated attacker
    could use this vulnerability to cause a denial-of-service (DoS). This issue only affected Ubuntu 14.04 ESM
    and Ubuntu 16.04 ESM. (CVE-2016-6630)

    Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize input. An attacker could use
    this vulnerability to bypass AllowRoot restrictions and deny rules for usernames. This issue only affected
    Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2016-9849)

    Emanuel Bronshtein discovered that phpMyAdmin would allow sensitive information to be leaked when the
    argument separator in a URL was not the default & value. An attacker could use this vulnerability to
    obtain the CSRF token of a user. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
    (CVE-2016-9866)

    Isaac Bennetch discovered that phpMyAdmin was incorrectly restricting user access due to the behavior of
    the substr function on some PHP versions. An attacker could use this vulnerability to bypass login
    restrictions established for users that have no password set. This issue only affected Ubuntu 14.04 ESM.
    This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2017-18264)

    Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize input in the form of parameters
    sent during a table editing operation. An attacker could use this vulnerability to trigger an endless
    recursion and cause a denial-of-service (DoS). This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04
    ESM. (CVE-2017-1000014)

    Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize input used to generate a web
    page. An authenticated attacker could use this vulnerability to execute CSS injection attacks. This issue
    only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2017-1000015)

    It was discovered that phpMyAdmin incorrectly handled certain input. An attacker could use this
    vulnerability to execute a cross-site scripting (XSS) attack via a crafted URL. This issue only affected
    Ubuntu 16.04 ESM. (CVE-2018-7260)

    It was discovered phpMyAdmin incorrectly handled database names. An attacker could possibly use this to
    trigger a cross-site scripting attack. This issue only affected Ubuntu 16.04 ESM and Ubuntu 18.04 ESM.
    (CVE-2018-12581)

    Daniel Le Gall discovered that phpMyAdmin would expose sensitive information to unauthorized actors due to
    an error in its transformation feature. An authenticated attacker could use this vulnerability to leak the
    contents of a local file. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-19968)

    It was discovered that phpMyAdmin incorrectly handled user input. An attacker could possibly use this to
    perform a cross-site scripting attack. This issue only affected Ubuntu 16.04 ESM. (CVE-2018-19970)

    It was discovered that phpMyAdmin failed to properly sanitize input. An attacker could use this
    vulnerability to execute an SQL injection attack via a specially crafted database name. This issue only
    affected Ubuntu 16.04 ESM. (CVE-2019-11768)

    It was discovered that phpMyAdmin incorrectly handled some requests. An attacker could possibly use this
    to perform a cross site request forgery attack. This issue only affected Ubuntu 16.04 ESM.
    (CVE-2019-12616)

    It was discovered that phpMyAdmin incorrectly handled some requests. An attacker could possibly use this
    to perform a cross site request forgery attack. This issue only affected Ubuntu 14.04 ESM and Ubuntu 18.04
    ESM. (CVE-2019-12922)

    It was discovered that phpMyAdmin failed to properly sanitize input. An attacker could use this
    vulnerability to execute an SQL injection attack via a specially crafted username. This issue only
    affected Ubuntu 16.04 ESM. (CVE-2019-6798)

    It was discovered that phpMyAdmin did not properly sanitize certain input. An attacker could use this
    vulnerability to possibly execute an HTML injection or a cross-site scripting (XSS) attack. This issue
    only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2019-19617)

    CSW Research Labs discovered that phpMyAdmin failed to properly sanitize input.

    An attacker could use this vulnerability to execute SQL injection attacks. This issue only affected Ubuntu
    16.04 ESM. (CVE-2020-5504)

    Giwan Go and Yelang Lee discovered that phpMyAdmin was vulnerable to an XSS attack in the transformation
    feature. If a victim were to click on a crafted link, an attacker could run malicious JavaScript on the
    victim's system. This issue only affected Ubuntu 20.04 ESM. (CVE-2020-26934)

    Andre S discovered that phpMyAdmin incorrectly handled certain SQL statements in the search feature. A
    remote, authenticated attacker could use this to inject malicious SQL into a query. This issue only
    affected Ubuntu 20.04 ESM. (CVE-2020-26935)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4843-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected phpmyadmin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phpmyadmin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'phpmyadmin', 'pkgver': '4:4.5.4.1-2ubuntu2.1+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'phpmyadmin', 'pkgver': '4:4.6.6-5ubuntu0.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'phpmyadmin', 'pkgver': '4:4.9.5+dfsg1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'phpmyadmin');
}
