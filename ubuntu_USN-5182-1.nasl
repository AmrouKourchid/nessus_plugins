#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5182-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183111);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-12625",
    "CVE-2020-12626",
    "CVE-2020-12640",
    "CVE-2020-12641",
    "CVE-2020-13964",
    "CVE-2020-13965",
    "CVE-2020-15562",
    "CVE-2020-16145",
    "CVE-2020-35730",
    "CVE-2021-44025",
    "CVE-2021-44026",
    "CVE-2021-46144"
  );
  script_xref(name:"USN", value:"5182-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : Roundcube Webmail vulnerabilities (USN-5182-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5182-1 advisory.

    It was discovered that Roundcube Webmail allowed JavaScript code to be present in the CDATA of an HTML
    message. A remote attacker could possibly use this issue to execute a cross-site scripting (XSS) attack.
    This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-12625)

    It was discovered that Roundcube Webmail incorrectly processed login and logout POST requests. An attacker
    could possibly use this issue to launch a cross-site request forgery (CSRF) attack and force an
    authenticated user to be logged out. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
    Ubuntu 20.04 ESM. (CVE-2020-12626)

    It was discovered that Roundcube Webmail incorrectly processed new plugin names in rcube_plugin_api.php.
    An attacker could possibly use this issue to obtain sensitive information from local files or to execute
    arbitrary code. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
    (CVE-2020-12640)

    It was discovered that Roundcube Webmail did not sanitize shell metacharacters recovered from variables in
    its configuration settings. An attacker could possibly use this issue to execute arbitrary code in the
    server. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-12641)

    It was discovered that Roundcube Webmail incorrectly sanitized characters in the username template object.
    An attacker could possibly use this issue to execute a cross-site scripting (XSS) attack. This issue only
    affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-13964)

    It was discovered that Roundcube Webmail allowed preview of text/html content. A remote attacker could
    possibly use this issue to send a malicious XML attachment via an email message and execute a cross-site
    scripting (XSS) attack. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
    (CVE-2020-13965)

    Andrea Cardaci discovered that Roundcube Webmail did not properly sanitize HTML special characters when
    dealing with HTML messages that contained an SVG element in the XML namespace. A remote attacker could
    possibly use this issue to execute a cross-site scripting (XSS) attack. This issue only affected Ubuntu
    18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-15562)

    Lukasz Pilorz discovered that Roundcube Webmail did not properly sanitize HTML special characters when
    dealing with HTML messages that contained SVG documents. A remote attacker could possibly use this issue
    to execute a cross-site scripting (XSS) attack. This issue only affected Ubuntu 18.04 ESM and Ubuntu 20.04
    ESM. (CVE-2020-16145)

    Alex Birnberg discovered that Roundcube Webmail incorrectly sanitized characters in plain text e-mail
    messages that included link reference elements. A remote attacker could possibly use this issue to execute
    a cross-site scripting (XSS) attack. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
    Ubuntu 20.04 ESM. (CVE-2020-35730)

    It was discovered that Roundcube Webmail did not properly sanitize HTML special characters in warning
    messages that contained an attachment's filename extension. A remote attacker could possibly use this
    issue to execute a cross-site scripting (XSS) attack. This issue only affected Ubuntu 16.04 ESM, Ubuntu
    18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-44025)

    It was discovered that Roundcube Webmail incorrectly managed session variables related to search
    functionalities. A remote attacker could possibly use this issue to execute a SQL injection attack. This
    issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-44026)

    It was discovered that Roundcube Webmail did not properly sanitize HTML special characters when dealing
    with HTML messages that contained CSS content. A remote attacker could possibly use this issue to execute
    a cross-site scripting (XSS) attack. This issue only affected Ubuntu 18.04 ESM, Ubuntu 20.04 ESM and
    Ubuntu 22.04 ESM. (CVE-2021-46144)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5182-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44026");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:roundcube-sqlite3");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'roundcube', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'roundcube-core', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'roundcube-mysql', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'roundcube-pgsql', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'roundcube-plugins', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'roundcube-sqlite3', 'pkgver': '1.2~beta+dfsg.1-0ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube-core', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube-mysql', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube-pgsql', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube-plugins', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'roundcube-sqlite3', 'pkgver': '1.3.6+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube-core', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube-mysql', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube-pgsql', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube-plugins', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'roundcube-sqlite3', 'pkgver': '1.4.3+dfsg.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube-core', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube-mysql', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube-pgsql', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube-plugins', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'roundcube-sqlite3', 'pkgver': '1.5.0+dfsg.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'roundcube / roundcube-core / roundcube-mysql / roundcube-pgsql / etc');
}
