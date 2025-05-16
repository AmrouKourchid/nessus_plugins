#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3350-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101354);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-2820",
    "CVE-2017-7511",
    "CVE-2017-7515",
    "CVE-2017-9083",
    "CVE-2017-9406",
    "CVE-2017-9408",
    "CVE-2017-9775"
  );
  script_xref(name:"USN", value:"3350-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : poppler vulnerabilities (USN-3350-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3350-1 advisory.

    Aleksandar Nikolic discovered that poppler incorrectly handled JPEG 2000 images. If a user or automated
    system were tricked into opening a crafted PDF file, an attacker could cause a denial of service or
    possibly execute arbitrary code with privileges of the user invoking the program. (CVE-2017-2820)

    Jiaqi Peng discovered that the poppler pdfunite tool incorrectly parsed certain malformed PDF documents.
    If a user or automated system were tricked into opening a crafted PDF file, an attacker could cause
    poppler to crash, resulting in a denial of service. (CVE-2017-7511)

    It was discovered that the poppler pdfunite tool incorrectly parsed certain malformed PDF documents. If a
    user or automated system were tricked into opening a crafted PDF file, an attacker could cause poppler to
    hang, resulting in a denial of service. (CVE-2017-7515)

    It was discovered that poppler incorrectly handled JPEG 2000 images. If a user or automated system were
    tricked into opening a crafted PDF file, an attacker could cause cause poppler to crash, resulting in a
    denial of service. (CVE-2017-9083)

    It was discovered that poppler incorrectly handled memory when processing PDF documents. If a user or
    automated system were tricked into opening a crafted PDF file, an attacker could cause poppler to consume
    resources, resulting in a denial of service. (CVE-2017-9406, CVE-2017-9408)

    Alberto Garcia, Francisco Oca, and Suleman Ali discovered that the poppler pdftocairo tool incorrectly
    parsed certain malformed PDF documents. If a user or automated system were tricked into opening a crafted
    PDF file, an attacker could cause poppler to crash, resulting in a denial of service. (CVE-2017-9775)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3350-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2820");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-cpp0', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-qt4-4', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-qt4-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'libpoppler44', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '14.04', 'pkgname': 'poppler-utils', 'pkgver': '0.24.5-2ubuntu4.5'},
    {'osver': '16.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-cpp0', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt4-4', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt4-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'libpoppler58', 'pkgver': '0.41.0-0ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'poppler-utils', 'pkgver': '0.41.0-0ubuntu1.2'}
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
    severity   : SECURITY_WARNING,
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
