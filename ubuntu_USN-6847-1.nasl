#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6847-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id(
    "CVE-2019-11471",
    "CVE-2020-23109",
    "CVE-2023-0996",
    "CVE-2023-29659",
    "CVE-2023-49460",
    "CVE-2023-49462",
    "CVE-2023-49463",
    "CVE-2023-49464"
  );
  script_xref(name:"USN", value:"6847-1");
  script_xref(name:"IAVB", value:"2024-B-0073-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 : libheif vulnerabilities (USN-6847-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6847-1 advisory.

    It was discovered that libheif incorrectly handled certain image data. An attacker could possibly use this
    issue to crash the program, resulting in a denial of service. This issue only affected Ubuntu 18.04 LTS.
    (CVE-2019-11471)

    Reza Mirzazade Farkhani discovered that libheif incorrectly handled certain image data. An attacker could
    possibly use this issue to crash the program, resulting in a denial of service. This issue only affected
    Ubuntu 20.04 LTS. (CVE-2020-23109)

    Eugene Lim discovered that libheif incorrectly handled certain image data. An attacker could possibly use
    this issue to crash the program, resulting in a denial of service. This issue only affected Ubuntu 18.04
    LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-0996)

    Min Jang discovered that libheif incorrectly handled certain image data. An attacker could possibly use
    this issue to crash the program, resulting in a denial of service. This issue only affected Ubuntu 20.04
    LTS and Ubuntu 22.04 LTS. (CVE-2023-29659)

    Yuchuan Meng discovered that libheif incorrectly handled certain image data. An attacker could possibly
    use this issue to crash the program, resulting in a denial of service. This issue only affected Ubuntu
    23.10. (CVE-2023-49460, CVE-2023-49462, CVE-2023-49463, CVE-2023-49464)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6847-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11471");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-49464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heif-gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heif-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-aomdec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-aomenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-dav1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-libde265");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-rav1e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-svtenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-x265");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libheif-dev', 'pkgver': '1.1.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libheif-examples', 'pkgver': '1.1.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libheif1', 'pkgver': '1.1.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'heif-gdk-pixbuf', 'pkgver': '1.6.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'heif-thumbnailer', 'pkgver': '1.6.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libheif-dev', 'pkgver': '1.6.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libheif-examples', 'pkgver': '1.6.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libheif1', 'pkgver': '1.6.1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'heif-gdk-pixbuf', 'pkgver': '1.12.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'heif-thumbnailer', 'pkgver': '1.12.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libheif-dev', 'pkgver': '1.12.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libheif-examples', 'pkgver': '1.12.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libheif1', 'pkgver': '1.12.0-2ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '23.10', 'pkgname': 'heif-gdk-pixbuf', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'heif-thumbnailer', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-dev', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-examples', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-aomdec', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-aomenc', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-dav1d', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-libde265', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-rav1e', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-svtenc', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif-plugin-x265', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libheif1', 'pkgver': '1.16.2-2ubuntu1.1', 'ubuntu_pro': FALSE}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heif-gdk-pixbuf / heif-thumbnailer / libheif-dev / libheif-examples / etc');
}
