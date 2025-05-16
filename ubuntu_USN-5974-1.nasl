#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5974-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173434);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-5685",
    "CVE-2018-9018",
    "CVE-2018-20184",
    "CVE-2018-20189",
    "CVE-2019-11006",
    "CVE-2020-12672",
    "CVE-2022-1270"
  );
  script_xref(name:"USN", value:"5974-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS : GraphicsMagick vulnerabilities (USN-5974-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5974-1 advisory.

    It was discovered that GraphicsMagick was not properly performing bounds checks when processing TGA image
    files, which could lead to a heap buffer overflow. If a user or automated system were tricked into
    processing a specially crafted TGA image file, an attacker could possibly use this issue to cause a denial
    of service or execute arbitrary code. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
    (CVE-2018-20184)

    It was discovered that GraphicsMagick was not properly validating bits per pixel data when processing DIB
    image files. If a user or automated system were tricked into processing a specially crafted DIB image
    file, an attacker could possibly use this issue to cause a denial of service. This issue only affected
    Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-20189)

    It was discovered that GraphicsMagick was not properly processing bit-field mask values in BMP image
    files, which could result in the execution of an infinite loop. If a user or automated system were tricked
    into processing a specially crafted BMP image file, an attacker could possibly use this issue to cause a
    denial of service. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-5685)

    It was discovered that GraphicsMagick was not properly validating data used in arithmetic operations when
    processing MNG image files, which could result in a divide-by-zero error. If a user or automated system
    were tricked into processing a specially crafted MNG image file, an attacker could possibly use this issue
    to cause a denial of service. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
    (CVE-2018-9018)

    It was discovered that GraphicsMagick was not properly performing bounds checks when processing MIFF image
    files, which could lead to a heap buffer overflow. If a user or automated system were tricked into
    processing a specially crafted MIFF image file, an attacker could possibly use this issue to cause a
    denial of service or expose sensitive information. This issue only affected Ubuntu 14.04 ESM and Ubuntu
    16.04 ESM. (CVE-2019-11006)

    It was discovered that GraphicsMagick did not properly magnify certain MNG image files, which could lead
    to a heap buffer overflow. If a user or automated system were tricked into processing a specially crafted
    MNG image file, an attacker could possibly use this issue to cause a denial of service or execute
    arbitrary code. This issue only affected Ubuntu 20.04 LTS. (CVE-2020-12672)

    It was discovered that GraphicsMagick was not properly performing bounds checks when parsing certain MIFF
    image files, which could lead to a heap buffer overflow. If a user or automated system were tricked into
    processing a specially crafted MIFF image file, an attacker could possibly use this issue to cause a
    denial of service or execute arbitrary code. (CVE-2022-1270)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5974-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11006");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++-q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick-q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick3");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.3.23-1ubuntu0.6+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.3.28-2ubuntu0.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.4+really1.3.35-1ubuntu0.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'graphicsmagick / graphicsmagick-imagemagick-compat / etc');
}
