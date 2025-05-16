##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4763-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147998);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-25289",
    "CVE-2021-25290",
    "CVE-2021-25291",
    "CVE-2021-25292",
    "CVE-2021-25293",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923"
  );
  script_xref(name:"USN", value:"4763-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Pillow vulnerabilities (USN-4763-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4763-1 advisory.

    It was discovered that Pillow incorrectly handled certain Tiff image files. If a user or automated system
    were tricked into opening a specially-crafted Tiff file, a remote attacker could cause Pillow to crash,
    resulting in a denial of service, or possibly execute arbitrary code. This issue only affected Ubuntu
    20.04 LTS and Ubuntu 20.10. (CVE-2021-25289, CVE-2021-25291)

    It was discovered that Pillow incorrectly handled certain Tiff image files. If a user or automated system
    were tricked into opening a specially-crafted Tiff file, a remote attacker could cause Pillow to crash,
    resulting in a denial of service, or possibly execute arbitrary code. (CVE-2021-25290)

    It was discovered that Pillow incorrectly handled certain PDF files. If a user or automated system were
    tricked into opening a specially-crafted PDF file, a remote attacker could cause Pillow to hang, resulting
    in a denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10.
    (CVE-2021-25292)

    It was discovered that Pillow incorrectly handled certain SGI image files. If a user or automated system
    were tricked into opening a specially-crafted SGI file, a remote attacker could possibly cause Pillow to
    crash, resulting in a denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
    Ubuntu 20.10. (CVE-2021-25293)

    Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that Pillow incorrectly handled certain
    BLP files. If a user or automated system were tricked into opening a specially-crafted BLP file, a remote
    attacker could possibly cause Pillow to consume resources, resulting in a denial of service. This issue
    only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2021-27921)

    Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that Pillow incorrectly handled certain
    ICNS files. If a user or automated system were tricked into opening a specially-crafted ICNS file, a
    remote attacker could possibly cause Pillow to consume resources, resulting in a denial of service.
    (CVE-2021-27922)

    Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that Pillow incorrectly handled certain
    ICO files. If a user or automated system were tricked into opening a specially-crafted ICO file, a remote
    attacker could possibly cause Pillow to consume resources, resulting in a denial of service.
    (CVE-2021-27922)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4763-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil.imagetk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '16.04', 'pkgname': 'python-imaging', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python-pil', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python-pil.imagetk', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python3-pil', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'python-pil', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python3-pil', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'python3-pil', 'pkgver': '7.0.0-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '7.0.0-4ubuntu0.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-imaging / python-pil / python-pil.imagetk / python3-pil / etc');
}
