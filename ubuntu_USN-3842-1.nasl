#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3842-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119581);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2018-4700");
  script_xref(name:"USN", value:"3842-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : CUPS vulnerability (USN-3842-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-3842-1 advisory.

    Jann Horn discovered that CUPS incorrectly handled session cookie randomness. A remote attacker could
    possibly use this issue to perform cross-site request forgery (CSRF) attacks.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3842-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ipp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
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
    {'osver': '14.04', 'pkgname': 'cups', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-bsd', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-client', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-common', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-core-drivers', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-daemon', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-ppdc', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'cups-server-common', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcups2', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcups2-dev', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupscgi1', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupscgi1-dev', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsimage2', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsmime1', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsmime1-dev', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsppdc1', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '14.04', 'pkgname': 'libcupsppdc1-dev', 'pkgver': '1.7.2-0ubuntu1.11'},
    {'osver': '16.04', 'pkgname': 'cups', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-bsd', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-client', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-common', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-core-drivers', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-daemon', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-ppdc', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'cups-server-common', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcups2', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcups2-dev', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupscgi1', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupscgi1-dev', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsimage2', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsmime1', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsmime1-dev', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsppdc1', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '16.04', 'pkgname': 'libcupsppdc1-dev', 'pkgver': '2.1.3-4ubuntu0.6'},
    {'osver': '18.04', 'pkgname': 'cups', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-bsd', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-client', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-common', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-core-drivers', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-daemon', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-ppdc', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'cups-server-common', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcups2', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcups2-dev', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcupscgi1', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcupsimage2', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcupsmime1', 'pkgver': '2.2.7-1ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libcupsppdc1', 'pkgver': '2.2.7-1ubuntu2.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-bsd / cups-client / cups-common / cups-core-drivers / etc');
}
