#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7082-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209555);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2024-41311");
  script_xref(name:"USN", value:"7082-1");
  script_xref(name:"IAVB", value:"2024-B-0162");

  script_name(english:"Ubuntu 24.04 LTS : libheif vulnerability (USN-7082-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-7082-1 advisory.

    Gerrard Tai discovered that libheif did not properly validate certain images, leading to out-of-bounds
    read and write vulnerability. If a user or automated system were tricked into opening a specially crafted
    file, an attacker could possibly use this issue to cause a denial of service or to obtain sensitive
    information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7082-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41311");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heif-gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heif-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-aomdec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-aomenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-dav1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-ffmpegdec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-j2kdec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-j2kenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-jpegdec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libheif-plugin-jpegenc");
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

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '24.04', 'pkgname': 'heif-gdk-pixbuf', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'heif-thumbnailer', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-dev', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-examples', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-aomdec', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-aomenc', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-dav1d', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-ffmpegdec', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-j2kdec', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-j2kenc', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-jpegdec', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-jpegenc', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-libde265', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-rav1e', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-svtenc', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif-plugin-x265', 'pkgver': '1.17.6-1ubuntu4.1'},
    {'osver': '24.04', 'pkgname': 'libheif1', 'pkgver': '1.17.6-1ubuntu4.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heif-gdk-pixbuf / heif-thumbnailer / libheif-dev / libheif-examples / etc');
}
