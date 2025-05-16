#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5167-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183614);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-20445",
    "CVE-2020-20446",
    "CVE-2020-20451",
    "CVE-2020-20453",
    "CVE-2020-20892",
    "CVE-2020-20902",
    "CVE-2020-21041",
    "CVE-2020-21688",
    "CVE-2020-21697",
    "CVE-2020-22016",
    "CVE-2020-22020",
    "CVE-2020-22021",
    "CVE-2020-22022",
    "CVE-2020-22025",
    "CVE-2020-22031",
    "CVE-2020-22032",
    "CVE-2020-22037",
    "CVE-2020-22040",
    "CVE-2020-22041",
    "CVE-2020-22042",
    "CVE-2020-22044",
    "CVE-2020-22046",
    "CVE-2020-22049",
    "CVE-2020-22054",
    "CVE-2020-35965",
    "CVE-2021-3566",
    "CVE-2021-38114",
    "CVE-2021-38171",
    "CVE-2021-38291"
  );
  script_xref(name:"USN", value:"5167-1");

  script_name(english:"Ubuntu 16.04 ESM : FFmpeg vulnerabilities (USN-5167-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5167-1 advisory.

    It was discovered that FFmpeg did not properly verify certain input when processing video and audio files.
    An attacker could possibly use this to send specially crafted input to the application, force a division
    by zero, and cause a denial of service (application crash). (CVE-2020-20445, CVE-2020-20446,
    CVE-2020-20453, CVE-2020-20892)

    It was discovered that FFmpeg did not properly perform certain bit shift and memory operations. An
    attacker could possibly use this issue to expose sensitive information. (CVE-2020-20902)

    It was discovered that FFmpeg did not properly perform memory management operations in various of its
    functions. An attacker could possibly use this issue to send specially crafted input to the application
    and cause a denial of service (application crash) or execute arbitrary code. (CVE-2020-21041,
    CVE-2020-20451, CVE-2020-21688, CVE-2020-21697, CVE-2020-22020, CVE-2020-22021, CVE-2020-22022,
    CVE-2020-22025, CVE-2020-22031, CVE-2020-22032, CVE-2020-22037, CVE-2020-22040, CVE-2020-22041,
    CVE-2020-22042, CVE-2020-22044)

    It was discovered that FFmpeg did not properly perform memory management operations in various of its
    functions. An attacker could possibly use this issue to send specially crafted input to the application
    and cause a denial of service (application crash) or execute arbitrary code. (CVE-2020-22016,
    CVE-2020-22046, CVE-2020-22049, CVE-2020-22054)

    It was discovered that FFmpeg did not properly perform memory management operations in various of its
    functions. An attacker could possibly use this issue to send specially crafted input to the application
    and cause a denial of service (application crash) or execute arbitrary code. (CVE-2020-35965)

    It was discovered that FFmpeg did not properly handle data assigned to the tty demuxer. An attacker could
    possibly use this issue to send specially crafted input to the application and expose sensitive
    information. (CVE-2021-3566)

    It was discovered that FFmpeg did not perform checks on function return values when encoding and
    formatting input video and audio files. An attacker could possibly use this issue to cause a denial of
    service (application crash) or execute arbitrary code. (CVE-2021-38114, CVE-2021-38171)

    It was discovered that FFmpeg did not properly sanitize function returned data when calculating frame
    duration values. An attacker could possibly use this issue to cause an assertion failure and then cause a
    denial of service (application crash). (CVE-2021-38291)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5167-1");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-ffmpeg-extra56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-ffmpeg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-ffmpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-ffmpeg54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-ffmpeg53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-ffmpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-ffmpeg3");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'ffmpeg', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libav-tools', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavcodec-ffmpeg-extra56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavcodec-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavdevice-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavfilter-ffmpeg5', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavformat-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavresample-ffmpeg2', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libavutil-ffmpeg54', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpostproc-ffmpeg53', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libswresample-ffmpeg1', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libswscale-ffmpeg3', 'pkgver': '7:2.8.17-0ubuntu0.1+esm4', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libav-tools / libavcodec-dev / libavcodec-extra / etc');
}
