##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5472-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161986);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-20445",
    "CVE-2020-20446",
    "CVE-2020-20450",
    "CVE-2020-20453",
    "CVE-2020-21041",
    "CVE-2020-21688",
    "CVE-2020-21697",
    "CVE-2020-22015",
    "CVE-2020-22016",
    "CVE-2020-22017",
    "CVE-2020-22019",
    "CVE-2020-22020",
    "CVE-2020-22021",
    "CVE-2020-22022",
    "CVE-2020-22023",
    "CVE-2020-22025",
    "CVE-2020-22026",
    "CVE-2020-22027",
    "CVE-2020-22028",
    "CVE-2020-22029",
    "CVE-2020-22030",
    "CVE-2020-22031",
    "CVE-2020-22032",
    "CVE-2020-22033",
    "CVE-2020-22034",
    "CVE-2020-22035",
    "CVE-2020-22036",
    "CVE-2020-22037",
    "CVE-2020-22042",
    "CVE-2020-35965",
    "CVE-2021-38114",
    "CVE-2021-38171",
    "CVE-2021-38291",
    "CVE-2022-1475"
  );
  script_xref(name:"USN", value:"5472-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : FFmpeg vulnerabilities (USN-5472-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5472-1 advisory.

    It was discovered that FFmpeg would attempt to divide by zero when using Linear Predictive Coding (LPC) or
    AAC codecs. An attacker could possibly use this issue to cause a denial of service. This issue only
    affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 21.10. (CVE-2020-20445, CVE-2020-20446,
    CVE-2020-20453)

    It was discovered that FFmpeg incorrectly handled certain input. An attacker could possibly use this issue
    to cause a denial of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2020-20450)

    It was discovered that FFmpeg incorrectly handled file conversion to APNG format. An attacker could
    possibly use this issue to cause a denial of service. This issue only affected Ubuntu 18.04 LTS and Ubuntu
    20.04 LTS. (CVE-2020-21041)

    It was discovered that FFmpeg incorrectly handled remuxing RTP-hint tracks. A remote attacker could
    possibly use this issue to execute arbitrary code. This issue only affected Ubuntu 18.04 LTS and Ubuntu
    20.04 LTS. (CVE-2020-21688)

    It was discovered that FFmpeg incorrectly handled certain specially crafted AVI files. An attacker could
    possibly use this issue to cause a denial of service. This issue only affected Ubuntu 18.04 LTS and Ubuntu
    20.04 LTS. (CVE-2020-21697)

    It was discovered that FFmpeg incorrectly handled writing MOV video tags. An attacker could possibly use
    this issue to cause a denial of service, obtain sensitive information or execute arbitrary code. This
    issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 21.10. (CVE-2020-22015)

    It was discovered that FFmpeg incorrectly handled writing MOV files. An attacker could possibly use this
    issue to cause a denial of service or other unspecified impact. This issue affected only Ubuntu 18.04 LTS.
    (CVE-2020-22016)

    It was discovered that FFmpeg incorrectly handled memory when using certain filters. An attacker could
    possibly use this issue to cause a denial of service or other unspecified impact. This issue only affected
    Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-22017, CVE-2020-22020, CVE-2020-22022, CVE-2020-22023,
    CVE-2022-22025, CVE-2020-22026, CVE-2020-22028, CVE-2020-22031, CVE-2020-22032, CVE-2020-22034,
    CVE-2020-22036, CVE-2020-22042)

    It was discovered that FFmpeg incorrectly handled memory when using certain filters. An attacker could
    possibly use this issue to cause a denial of service or other unspecified impact. This issue only affected
    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 21.10. (CVE-2020-22019, CVE-2020-22021, CVE-2020-22033)

    It was discovered that FFmpeg incorrectly handled memory when using certain filters. An attacker could
    possibly use this issue to cause a denial of service or other unspecified impact. This issue only affected
    Ubuntu 21.10. (CVE-2020-22027, CVE-2020-22029, CVE-2020-22030, CVE-2020-22035)

    It was discovered that FFmpeg incorrectly handled certain specially crafted JPEG files. An attacker could
    possibly use this issue to obtain sensitive information. This issue only affected Ubuntu 18.04 LTS, Ubuntu
    20.04 LTS and Ubuntu 21.10. (CVE-2020-22037)

    It was discovered that FFmpeg incorrectly performed calculations in EXR codec. An attacker could possibly
    use this issue to cause a denial of service. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04
    LTS. (CVE-2020-35965)

    It was discovered that FFmpeg did not verify return values of functions init_vlc and init_get_bits. An
    attacker could possibly use this issue to cause a denial of service or other unspecified impact. This
    issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 21.10. (CVE-2021-38114, CVE-2021-38171)

    It was discovered that FFmpeg incorrectly handled certain specially crafted files. An attacker could
    possibly use this issue to cause a denial of service. This issue only affected Ubuntu 21.10 and Ubuntu
    22.04 LTS. (CVE-2022-1475)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5472-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ffmpeg', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra6', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter6', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavformat57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavresample3', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavutil55', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc54', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswresample2', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswscale4', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavresample4', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libavcodec-dev / libavcodec-extra / libavcodec-extra57 / etc');
}
