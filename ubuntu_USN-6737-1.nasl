#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6737-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193515);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2024-2961");
  script_xref(name:"USN", value:"6737-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 : GNU C Library vulnerability (USN-6737-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-6737-1 advisory.

    Charles Fol discovered that the GNU C Library iconv feature incorrectly handled certain input sequences.
    An attacker could use this issue to cause the GNU C Library to crash, resulting in a denial of service, or
    possibly execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6737-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-devtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-lse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'glibc-source', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc-bin', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-armel', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-i386', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-lse', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-pic', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-prof', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-s390', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'libc6-x32', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'locales', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'locales-all', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '20.04', 'pkgname': 'nscd', 'pkgver': '2.31-0ubuntu9.15'},
    {'osver': '22.04', 'pkgname': 'glibc-source', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc-bin', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc-devtools', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-dev', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-i386', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-prof', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-s390', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libc6-x32', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'locales', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'locales-all', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'nscd', 'pkgver': '2.35-0ubuntu3.7'},
    {'osver': '23.10', 'pkgname': 'glibc-source', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc-bin', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc-dev-bin', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc-devtools', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-amd64', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-dev', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-i386', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-prof', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-s390', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'libc6-x32', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'locales', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'locales-all', 'pkgver': '2.38-1ubuntu6.2'},
    {'osver': '23.10', 'pkgname': 'nscd', 'pkgver': '2.38-1ubuntu6.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc-devtools / libc6 / etc');
}
