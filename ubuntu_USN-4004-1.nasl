#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4004-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183607);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2019-8457");
  script_xref(name:"USN", value:"4004-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Berkeley DB vulnerability (USN-4004-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-4004-1 advisory.

    It was discovered that Berkeley DB incorrectly handled certain inputs. An attacker could possibly use this
    issue to read sensitive information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4004-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:db5.3-sql-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:db5.3-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-java-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-java-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-java-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-sql-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-stl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-stl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdb5.3-tcl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'db5.3-sql-util', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'db5.3-util', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3++', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3++-dev', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-dev', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-java', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-java-dev', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-java-gcj', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-java-jni', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-sql', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-sql-dev', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-stl', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-stl-dev', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libdb5.3-tcl', 'pkgver': '5.3.28-11ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'db5.3-sql-util', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'db5.3-util', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3++', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3++-dev', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-dev', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-java', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-java-dev', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-java-jni', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-sql', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-sql-dev', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-stl', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-stl-dev', 'pkgver': '5.3.28-13.1ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libdb5.3-tcl', 'pkgver': '5.3.28-13.1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'db5.3-sql-util / db5.3-util / libdb5.3 / libdb5.3++ / etc');
}
