#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3627-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109199);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-15710",
    "CVE-2017-15715",
    "CVE-2018-1283",
    "CVE-2018-1301",
    "CVE-2018-1303",
    "CVE-2018-1312"
  );
  script_xref(name:"USN", value:"3627-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Apache HTTP Server vulnerabilities (USN-3627-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3627-1 advisory.

    Alex Nichols and Jakob Hirsch discovered that the Apache HTTP Server mod_authnz_ldap module incorrectly
    handled missing charset encoding headers. A remote attacker could possibly use this issue to cause the
    server to crash, resulting in a denial of service. (CVE-2017-15710)

    Elar Lang discovered that the Apache HTTP Server incorrectly handled certain characters specified in
    <FilesMatch>. A remote attacker could possibly use this issue to upload certain files, contrary to
    expectations. (CVE-2017-15715)

    It was discovered that the Apache HTTP Server mod_session module incorrectly handled certain headers. A
    remote attacker could possibly use this issue to influence session data. (CVE-2018-1283)

    Robert Swiecki discovered that the Apache HTTP Server incorrectly handled certain requests. A remote
    attacker could possibly use this issue to cause the server to crash, leading to a denial of service.
    (CVE-2018-1301)

    Robert Swiecki discovered that the Apache HTTP Server mod_cache_socache module incorrectly handled certain
    headers. A remote attacker could possibly use this issue to cause the server to crash, leading to a denial
    of service. (CVE-2018-1303)

    Nicolas Daniels discovered that the Apache HTTP Server incorrectly generated the nonce when creating HTTP
    Digest authentication challenges. A remote attacker could possibly use this issue to replay HTTP requests
    across a cluster of servers. (CVE-2018-1312)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3627-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-macro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
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
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'apache2', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-event', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-itk', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-prefork', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-mpm-worker', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'apache2.2-bin', 'pkgver': '2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-macro', 'pkgver': '1:2.4.7-1ubuntu4.20'},
    {'osver': '14.04', 'pkgname': 'libapache2-mod-proxy-html', 'pkgver': '1:2.4.7-1ubuntu4.20'},
    {'osver': '16.04', 'pkgname': 'apache2', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.18-2ubuntu3.8'},
    {'osver': '16.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.18-2ubuntu3.8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / etc');
}
