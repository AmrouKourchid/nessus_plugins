#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7476-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235158);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id(
    "CVE-2021-41125",
    "CVE-2022-0577",
    "CVE-2024-1892",
    "CVE-2024-1968",
    "CVE-2024-3572",
    "CVE-2024-3574"
  );
  script_xref(name:"USN", value:"7476-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS : Scrapy vulnerabilities (USN-7476-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-7476-1 advisory.

    It was discovered that Scrapy improperly exposed HTTP authentication

    credentials to request targets, including during redirects. An attacker

    could use this issue to gain unauthorized access to user accounts. This issue only affected Ubuntu 18.04
    LTS and Ubuntu 20.04 LTS. (CVE-2021-41125)

    It was discovered that Scrapy did not remove the cookie header during cross-domain redirects. An attacker
    could possibly use this issue to gain unauthorized access to user accounts. This issue only affected
    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-0577)

    It was discovered that Scrapy inefficiently parsed XML content. An attacker could use this issue to cause
    a denial of service by sending a crafted XML response. This issue only affected Ubuntu 18.04 LTS, Ubuntu
    20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2024-1892)

    It was discovered that Scrapy did not properly check response size during decompression. An attacker could
    send a crafted response that would exhaust memory and cause a denial of service. This issue only affected
    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2024-3572)

    It was discovered that Scrapy did not remove the authorization header during cross-domain redirects. An
    attacker could possibly use this issue to gain unauthorized access to user accounts. This issue only
    affected

    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2024-3574)

    It was discovered that Scrapy did not remove the authorization header during redirects that change scheme
    but remain in the same domain. This issue could possibly be used by an attacker to expose sensitive

    information or to gain unauthorized access to user accounts. (CVE-2024-1968)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7476-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-scrapy and / or python3-scrapy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0577");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2021-41125");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-scrapy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-scrapy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'python-scrapy', 'pkgver': '1.5.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE, 'cves': ['CVE-2021-41125', 'CVE-2022-0577', 'CVE-2024-1892', 'CVE-2024-1968', 'CVE-2024-3572', 'CVE-2024-3574']},
    {'osver': '18.04', 'pkgname': 'python3-scrapy', 'pkgver': '1.5.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE, 'cves': ['CVE-2021-41125', 'CVE-2022-0577', 'CVE-2024-1892', 'CVE-2024-1968', 'CVE-2024-3572', 'CVE-2024-3574']},
    {'osver': '20.04', 'pkgname': 'python3-scrapy', 'pkgver': '1.7.3-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE, 'cves': ['CVE-2021-41125', 'CVE-2022-0577', 'CVE-2024-1892', 'CVE-2024-1968', 'CVE-2024-3572', 'CVE-2024-3574']},
    {'osver': '22.04', 'pkgname': 'python3-scrapy', 'pkgver': '2.5.1-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE, 'cves': ['CVE-2022-0577', 'CVE-2024-1892', 'CVE-2024-1968', 'CVE-2024-3572', 'CVE-2024-3574']},
    {'osver': '24.04', 'pkgname': 'python3-scrapy', 'pkgver': '2.11.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE, 'cves': ['CVE-2024-1968', 'CVE-2024-3574']}
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
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-scrapy / python3-scrapy');
}
