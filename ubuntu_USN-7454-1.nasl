#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7454-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234800);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/24");

  script_cve_id("CVE-2025-1632", "CVE-2025-25724");
  script_xref(name:"IAVA", value:"2024-A-0834");
  script_xref(name:"USN", value:"7454-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 : libarchive vulnerabilities (USN-7454-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-7454-1 advisory.

    It was discovered that the libarchive bsdunzip utility incorrectly handled certain ZIP archive files. If a
    user or automated system were tricked into processing a specially crafted ZIP archive, an attacker could
    use this issue to cause libarchive to crash, resulting in a denial of service, or possibly execute
    arbitrary code. This issue only affected Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04. (CVE-2025-1632)

    It was discovered that libarchive incorrectly handled certain TAR archive files. If a user or automated
    system were tricked into processing a specially crafted TAR archive, an attacker could use this issue to
    cause libarchive to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2025-25724)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7454-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1632");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:25.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive13t64");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release || '25.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10 / 25.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libarchive-dev', 'pkgver': '3.4.0-2ubuntu1.5', 'cves': ['CVE-2025-25724']},
    {'osver': '20.04', 'pkgname': 'libarchive-tools', 'pkgver': '3.4.0-2ubuntu1.5', 'cves': ['CVE-2025-25724']},
    {'osver': '20.04', 'pkgname': 'libarchive13', 'pkgver': '3.4.0-2ubuntu1.5', 'cves': ['CVE-2025-25724']},
    {'osver': '22.04', 'pkgname': 'libarchive-dev', 'pkgver': '3.6.0-1ubuntu1.4', 'cves': ['CVE-2025-25724']},
    {'osver': '22.04', 'pkgname': 'libarchive-tools', 'pkgver': '3.6.0-1ubuntu1.4', 'cves': ['CVE-2025-25724']},
    {'osver': '22.04', 'pkgname': 'libarchive13', 'pkgver': '3.6.0-1ubuntu1.4', 'cves': ['CVE-2025-25724']},
    {'osver': '24.04', 'pkgname': 'libarchive-dev', 'pkgver': '3.7.2-2ubuntu0.4', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '24.04', 'pkgname': 'libarchive-tools', 'pkgver': '3.7.2-2ubuntu0.4', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '24.04', 'pkgname': 'libarchive13t64', 'pkgver': '3.7.2-2ubuntu0.4', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '24.10', 'pkgname': 'libarchive-dev', 'pkgver': '3.7.4-1ubuntu0.2', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '24.10', 'pkgname': 'libarchive-tools', 'pkgver': '3.7.4-1ubuntu0.2', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '24.10', 'pkgname': 'libarchive13t64', 'pkgver': '3.7.4-1ubuntu0.2', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '25.04', 'pkgname': 'libarchive-dev', 'pkgver': '3.7.7-0ubuntu2.1', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '25.04', 'pkgname': 'libarchive-tools', 'pkgver': '3.7.7-0ubuntu2.1', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']},
    {'osver': '25.04', 'pkgname': 'libarchive13t64', 'pkgver': '3.7.7-0ubuntu2.1', 'cves': ['CVE-2025-1632', 'CVE-2025-25724']}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libarchive-dev / libarchive-tools / libarchive13 / libarchive13t64');
}
