#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7424-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234028);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2024-8176");
  script_xref(name:"IAVA", value:"2025-A-0186");
  script_xref(name:"USN", value:"7424-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS / 24.10 : Expat vulnerability (USN-7424-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-7424-1 advisory.

    It was discovered that Expat could crash due to stack overflow when

    processing XML documents with deeply nested entity references. If a user

    or automated system were tricked into processing specially crafted XML

    input, an attacker could use this issue to cause a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7424-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected expat, libexpat1 and / or libexpat1-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexpat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexpat1-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'osver': '22.04', 'pkgname': 'expat', 'pkgver': '2.4.7-1ubuntu0.6'},
    {'osver': '22.04', 'pkgname': 'libexpat1', 'pkgver': '2.4.7-1ubuntu0.6'},
    {'osver': '22.04', 'pkgname': 'libexpat1-dev', 'pkgver': '2.4.7-1ubuntu0.6'},
    {'osver': '24.04', 'pkgname': 'expat', 'pkgver': '2.6.1-2ubuntu0.3'},
    {'osver': '24.04', 'pkgname': 'libexpat1', 'pkgver': '2.6.1-2ubuntu0.3'},
    {'osver': '24.04', 'pkgname': 'libexpat1-dev', 'pkgver': '2.6.1-2ubuntu0.3'},
    {'osver': '24.10', 'pkgname': 'expat', 'pkgver': '2.6.2-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libexpat1', 'pkgver': '2.6.2-2ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libexpat1-dev', 'pkgver': '2.6.2-2ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'expat / libexpat1 / libexpat1-dev');
}
