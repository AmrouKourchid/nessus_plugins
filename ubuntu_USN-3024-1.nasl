#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3024-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91954);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-5174",
    "CVE-2015-5345",
    "CVE-2015-5346",
    "CVE-2015-5351",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763",
    "CVE-2016-3092"
  );
  script_xref(name:"USN", value:"3024-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Tomcat vulnerabilities (USN-3024-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3024-1 advisory.

    It was discovered that Tomcat incorrectly handled pathnames used by web applications in a getResource,
    getResourceAsStream, or getResourcePaths call. A remote attacker could use this issue to possibly list a
    parent directory . This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
    (CVE-2015-5174)

    It was discovered that the Tomcat mapper component incorrectly handled redirects. A remote attacker could
    use this issue to determine the existence of a directory. This issue only affected Ubuntu 12.04 LTS,
    Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5345)

    It was discovered that Tomcat incorrectly handled different session settings when multiple versions of the
    same web application was deployed. A remote attacker could possibly use this issue to hijack web sessions.
    This issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5346)

    It was discovered that the Tomcat Manager and Host Manager applications incorrectly handled new requests.
    A remote attacker could possibly use this issue to bypass CSRF protection mechanisms. This issue only
    affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5351)

    It was discovered that Tomcat did not place StatusManagerServlet on the RestrictedServlets list. A remote
    attacker could possibly use this issue to read arbitrary HTTP requests, including session ID values. This
    issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-0706)

    It was discovered that the Tomcat session-persistence implementation incorrectly handled session
    attributes. A remote attacker could possibly use this issue to execute arbitrary code in a privileged
    context. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-0714)

    It was discovered that the Tomcat setGlobalContext method incorrectly checked if callers were authorized.
    A remote attacker could possibly use this issue to read or wite to arbitrary application data, or cause a
    denial of service. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
    (CVE-2016-0763)

    It was discovered that the Tomcat Fileupload library incorrectly handled certain upload requests. A remote
    attacker could possibly use this issue to cause a denial of service. (CVE-2016-3092)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3024-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5351");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-0714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet3.0-java");
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
    {'osver': '14.04', 'pkgname': 'libservlet3.0-java', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'libtomcat7-java', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'tomcat7', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'tomcat7-admin', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'tomcat7-common', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'tomcat7-examples', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '14.04', 'pkgname': 'tomcat7-user', 'pkgver': '7.0.52-1ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libservlet3.0-java', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'libtomcat7-java', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'tomcat7', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'tomcat7-admin', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'tomcat7-common', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'tomcat7-examples', 'pkgver': '7.0.68-1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'tomcat7-user', 'pkgver': '7.0.68-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libservlet3.0-java / libtomcat7-java / tomcat7 / tomcat7-admin / etc');
}
