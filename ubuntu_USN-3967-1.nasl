#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3967-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124678);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-15822",
    "CVE-2019-11338",
    "CVE-2019-11339",
    "CVE-2019-9718",
    "CVE-2019-9721"
  );
  script_xref(name:"USN", value:"3967-1");

  script_name(english:"Ubuntu 18.04 LTS : FFmpeg vulnerabilities (USN-3967-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-3967-1 advisory.

    It was discovered that FFmpeg contained multiple security issues when handling certain multimedia files.
    If a user were tricked into opening a crafted multimedia file, an attacker could cause a denial of service
    via application crash.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3967-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ffmpeg', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra57', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec57', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice57', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra6', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter6', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavformat57', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavresample3', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libavutil55', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc54', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libswresample2', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libswscale4', 'pkgver': '7:3.4.6-0ubuntu0.18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libavcodec-dev / libavcodec-extra / libavcodec-extra57 / etc');
}
