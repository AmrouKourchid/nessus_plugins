#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2519-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81572);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2013-7423",
    "CVE-2014-9402",
    "CVE-2015-1472",
    "CVE-2015-1473"
  );
  script_bugtraq_id(71670, 72428, 72499);
  script_xref(name:"USN", value:"2519-1");

  script_name(english:"Ubuntu 14.04 LTS : GNU C Library vulnerabilities (USN-2519-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2519-1 advisory.

    Arnaud Le Blanc discovered that the GNU C Library incorrectly handled file descriptors when resolving DNS
    queries under high load. This may cause a denial of service in other applications, or an information leak.
    This issue only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2013-7423)

    It was discovered that the GNU C Library incorrectly handled receiving a positive answer while processing
    the network name when performing DNS resolution. A remote attacker could use this issue to cause the GNU C
    Library to hang, resulting in a denial of service. (CVE-2014-9402)

    Joseph Myers discovered that the GNU C Library wscanf function incorrectly handled memory. A remote
    attacker could possibly use this issue to cause the GNU C Library to crash, resulting in a denial of
    service, or possibly execute arbitrary code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS
    and Ubuntu 14.10. (CVE-2015-1472, CVE-2015-1473)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2519-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1472");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-9402");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dns-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-files-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eglibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
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
    {'osver': '14.04', 'pkgname': 'eglibc-source', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc-bin', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-armel', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev-ppc64', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-i386', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-pic', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-ppc64', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-prof', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-udeb', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libc6-x32', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libnss-dns-udeb', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'libnss-files-udeb', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'multiarch-support', 'pkgver': '2.19-0ubuntu6.6'},
    {'osver': '14.04', 'pkgname': 'nscd', 'pkgver': '2.19-0ubuntu6.6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eglibc-source / libc-bin / libc-dev-bin / libc6 / libc6-amd64 / etc');
}
