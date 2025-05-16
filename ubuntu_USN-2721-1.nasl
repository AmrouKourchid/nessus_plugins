#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2721-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85579);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-3580",
    "CVE-2014-8108",
    "CVE-2015-0202",
    "CVE-2015-0248",
    "CVE-2015-0251",
    "CVE-2015-3184",
    "CVE-2015-3187"
  );
  script_xref(name:"USN", value:"2721-1");

  script_name(english:"Ubuntu 14.04 LTS : Subversion vulnerabilities (USN-2721-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2721-1 advisory.

    It was discovered that the Subversion mod_dav_svn module incorrectly handled REPORT requests for a
    resource that does not exist. A remote attacker could use this issue to cause the server to crash,
    resulting in a denial of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
    (CVE-2014-3580)

    It was discovered that the Subversion mod_dav_svn module incorrectly handled requests requiring a lookup
    for a virtual transaction name that does not exist. A remote attacker could use this issue to cause the
    server to crash, resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS.
    (CVE-2014-8108)

    Evgeny Kotkov discovered that the Subversion mod_dav_svn module incorrectly handled large numbers of
    REPORT requests. A remote attacker could use this issue to cause the server to crash, resulting in a
    denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-0202)

    Evgeny Kotkov discovered that the Subversion mod_dav_svn and svnserve modules incorrectly certain crafted
    parameter combinations. A remote attacker could use this issue to cause the server to crash, resulting in
    a denial of service. (CVE-2015-0248)

    Ivan Zhakov discovered that the Subversion mod_dav_svn module incorrectly handled crafted v1 HTTP protocol
    request sequences. A remote attacker could use this issue to spoof the svn:author property.
    (CVE-2015-0251)

    C. Michael Pilato discovered that the Subversion mod_dav_svn module incorrectly restricted anonymous
    access. A remote attacker could use this issue to read hidden files via the path name. This issue only
    affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3184)

    C. Michael Pilato discovered that Subversion incorrectly handled path-based authorization. A remote
    attacker could use this issue to obtain sensitive path information. (CVE-2015-3187)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2721-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3184");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-3187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'libapache2-mod-svn', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libapache2-svn', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libsvn-dev', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libsvn-java', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libsvn-perl', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libsvn-ruby1.8', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'libsvn1', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'python-subversion', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'ruby-svn', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'subversion', 'pkgver': '1.8.8-1ubuntu3.2'},
    {'osver': '14.04', 'pkgname': 'subversion-tools', 'pkgver': '1.8.8-1ubuntu3.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-svn / libapache2-svn / libsvn-dev / libsvn-java / etc');
}
