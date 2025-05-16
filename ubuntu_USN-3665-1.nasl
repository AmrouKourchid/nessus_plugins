#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3665-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110264);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-12616",
    "CVE-2017-12617",
    "CVE-2017-15706",
    "CVE-2018-1304",
    "CVE-2018-1305",
    "CVE-2018-8014"
  );
  script_xref(name:"USN", value:"3665-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : Tomcat vulnerabilities (USN-3665-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-3665-1 advisory.

    It was discovered that Tomcat incorrectly handled being configured with HTTP PUTs enabled. A remote
    attacker could use this issue to upload a JSP file to the server and execute arbitrary code. This issue
    only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2017-12616, CVE-2017-12617)

    It was discovered that Tomcat contained incorrect documentation regarding description of the search
    algorithm used by the CGI Servlet to identify which script to execute. This issue only affected Ubuntu
    17.10. (CVE-2017-15706)

    It was discovered that Tomcat incorrectly handled en empty string URL pattern in security constraint
    definitions. A remote attacker could possibly use this issue to gain access to web application resources,
    contrary to expectations. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10.
    (CVE-2018-1304)

    It was discovered that Tomcat incorrectly handled applying certain security constraints. A remote attacker
    could possibly access certain resources, contrary to expectations. This issue only affected Ubuntu 14.04
    LTS, Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1305)

    It was discovered that the Tomcat CORS filter default settings were insecure and would enable
    'supportsCredentials' for all origins, contrary to expectations. (CVE-2018-8014)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3665-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat VirtualDirContext Class File Handling Remote JSP Source Code Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat8-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat8-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet3.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet3.1-java");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libservlet3.0-java', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'libtomcat7-java', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'tomcat7', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'tomcat7-admin', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'tomcat7-common', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'tomcat7-examples', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '14.04', 'pkgname': 'tomcat7-user', 'pkgver': '7.0.52-1ubuntu0.14'},
    {'osver': '16.04', 'pkgname': 'libservlet3.1-java', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'libtomcat8-java', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'tomcat8', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'tomcat8-admin', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'tomcat8-common', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'tomcat8-examples', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'tomcat8-user', 'pkgver': '8.0.32-1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'libservlet3.1-java', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libtomcat8-embed-java', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libtomcat8-java', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'tomcat8', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'tomcat8-admin', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'tomcat8-common', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'tomcat8-examples', 'pkgver': '8.5.30-1ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'tomcat8-user', 'pkgver': '8.5.30-1ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libservlet3.0-java / libservlet3.1-java / libtomcat7-java / etc');
}
