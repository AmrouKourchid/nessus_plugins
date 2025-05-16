#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7435-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234344);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2024-7254");
  script_xref(name:"USN", value:"7435-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS / 24.10 : Protocol Buffers vulnerability (USN-7435-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-7435-1 advisory.

    It was discovered that Protocol Buffers incorrectly handled memory when receiving malicious input using
    the Java bindings. An attacker could possibly use this issue to cause a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7435-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:elpa-protobuf-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf-lite32t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotobuf32t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libprotoc32t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-google-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:protobuf-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-google-protobuf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'elpa-protobuf-mode', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-java', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotobuf-lite23', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotobuf23', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotoc-dev', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libprotoc23', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'protobuf-compiler', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'python3-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '22.04', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.12.4-1ubuntu7.22.04.2'},
    {'osver': '24.04', 'pkgname': 'elpa-protobuf-mode', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotobuf-java', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotobuf-lite32t64', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotobuf32t64', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotoc-dev', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libprotoc32t64', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'php-google-protobuf', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'protobuf-compiler', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'python3-protobuf', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.21.12-8.2ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'elpa-protobuf-mode', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotobuf-dev', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotobuf-java', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotobuf-lite32t64', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotobuf32t64', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotoc-dev', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libprotoc32t64', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'php-google-protobuf', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'protobuf-compiler', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'python3-protobuf', 'pkgver': '3.21.12-9ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'ruby-google-protobuf', 'pkgver': '3.21.12-9ubuntu1.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'elpa-protobuf-mode / libprotobuf-dev / libprotobuf-java / etc');
}
