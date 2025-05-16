#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6508-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186209);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-23804",
    "CVE-2022-37050",
    "CVE-2022-37051",
    "CVE-2022-37052",
    "CVE-2022-38349"
  );
  script_xref(name:"USN", value:"6508-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS : poppler vulnerabilities (USN-6508-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6508-1 advisory.

    It was discovered that poppler incorrectly handled certain malformed PDF files. If a user or an automated
    system were tricked into opening a specially crafted PDF file, a remote attacker could possibly use this
    issue to cause a denial of service. This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu
    20.04 LTS. (CVE-2020-23804)

    It was discovered that poppler incorrectly handled certain malformed PDF files. If a user or an automated
    system were tricked into opening a specially crafted PDF file, a remote attacker could possibly use this
    issue to cause a denial of service. (CVE-2022-37050, CVE-2022-37051, CVE-2022-37052, CVE-2022-38349)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6508-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38349");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-23804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-cpp0', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt4-4', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt4-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpoppler58', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'poppler-utils', 'pkgver': '0.41.0-0ubuntu1.16+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-cpp0v5', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpoppler73', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'poppler-utils', 'pkgver': '0.62.0-2ubuntu2.14+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-cpp0v5', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpoppler97', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'poppler-utils', 'pkgver': '0.86.1-0ubuntu1.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-cpp0v5', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-dev', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpoppler118', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'poppler-utils', 'pkgver': '22.02.0-2ubuntu0.3', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-poppler-0.18 / libpoppler-cpp-dev / libpoppler-cpp0 / etc');
}
