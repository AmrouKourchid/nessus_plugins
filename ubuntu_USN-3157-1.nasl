#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3157-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(95873);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2016-9949", "CVE-2016-9950", "CVE-2016-9951");
  script_xref(name:"USN", value:"3157-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Apport vulnerabilities (USN-3157-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3157-1 advisory.

    Donncha O Cearbhaill discovered that the crash file parser in Apport improperly treated the CrashDB field
    as python code. An attacker could use this to convince a user to open a maliciously crafted crash file and
    execute arbitrary code with the privileges of that user. This issue only affected Ubuntu 14.04 LTS and
    Ubuntu 16.04 LTS. (CVE-2016-9949)

    Donncha O Cearbhaill discovered that Apport did not properly sanitize the Package and SourcePackage fields
    in crash files before processing package specific hooks. An attacker could use this to convince a user to
    open a maliciously crafted crash file and execute arbitrary code with the privileges of that user.
    (CVE-2016-9950)

    Donncha O Cearbhaill discovered that Apport would offer to restart an application based on the contents of
    the RespawnCommand or ProcCmdline fields in a crash file. An attacker could use this to convince a user to
    open a maliciously crafted crash file and execute arbitrary code with the privileges of that user.
    (CVE-2016-9951)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3157-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9950");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-noui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dh-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-problem-report");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
    {'osver': '14.04', 'pkgname': 'apport', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'apport-gtk', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'apport-kde', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'apport-noui', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'apport-retrace', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'dh-apport', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'python-apport', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'python-problem-report', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'python3-apport', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '14.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.14.1-0ubuntu3.23'},
    {'osver': '16.04', 'pkgname': 'apport', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'python-apport', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'python-problem-report', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.1-0ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.1-0ubuntu2.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apport / apport-gtk / apport-kde / apport-noui / apport-retrace / etc');
}
