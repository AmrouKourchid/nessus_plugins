#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2291-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76586);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-2494",
    "CVE-2014-4207",
    "CVE-2014-4258",
    "CVE-2014-4260"
  );
  script_bugtraq_id(
    68564,
    68573,
    68579,
    68593
  );
  script_xref(name:"USN", value:"2291-1");

  script_name(english:"Ubuntu 14.04 LTS : MySQL vulnerabilities (USN-2291-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2291-1 advisory.

    Multiple security issues were discovered in MySQL and this update includes a new upstream MySQL version to
    fix these issues. MySQL has been updated to 5.5.38.

    In addition to security fixes, the updated packages contain bug fixes, new features, and possibly
    incompatible changes.

    Please see the following for more information:
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-38.html
    http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2291-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4258");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-4260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libmysqlclient18', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libmysqld-pic', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-client', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-client-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-client-core-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-common', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-server', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-server-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-server-core-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-source-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.5.38-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'mysql-testsuite-5.5', 'pkgver': '5.5.38-0ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient18 / libmysqld-dev / etc');
}
