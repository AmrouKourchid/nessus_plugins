#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2799. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154752);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2016-1516",
    "CVE-2017-12597",
    "CVE-2017-12598",
    "CVE-2017-12599",
    "CVE-2017-12601",
    "CVE-2017-12603",
    "CVE-2017-12604",
    "CVE-2017-12605",
    "CVE-2017-12606",
    "CVE-2017-12862",
    "CVE-2017-12863",
    "CVE-2017-12864",
    "CVE-2017-17760",
    "CVE-2017-1000450",
    "CVE-2018-5268",
    "CVE-2018-5269",
    "CVE-2019-14493",
    "CVE-2019-15939"
  );

  script_name(english:"Debian DLA-2799-1 : opencv - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2799 advisory.

    Several security vulnerabilities have been discovered in OpenCV, the Open Computer Vision Library. Buffer
    overflows, NULL pointer dereferences and out-of-bounds write errors may lead to a denial-of-service or
    other unspecified impact. For Debian 9 stretch, these problems have been fixed in version
    2.4.9.1+dfsg1-2+deb9u1. We recommend that you upgrade your opencv packages. For the detailed security
    status of opencv please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/opencv Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=886282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/opencv");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-1000450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12862");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15939");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/opencv");
  script_set_attribute(attribute:"solution", value:
"Upgrade the opencv packages.

For Debian 9 stretch, these problems have been fixed in version 2.4.9.1+dfsg1-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12864");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui2.4-deb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-opencv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libcv-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcv2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcvaux-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcvaux2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libhighgui-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libhighgui2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-calib3d-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-calib3d2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-contrib-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-contrib2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-core-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-core2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-features2d-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-features2d2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-flann-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-flann2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-gpu-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-gpu2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-highgui-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-highgui2.4-deb0', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-imgproc-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-imgproc2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-legacy-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-legacy2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ml-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ml2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-objdetect-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-objdetect2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ocl-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ocl2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-photo-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-photo2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-stitching-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-stitching2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-superres-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-superres2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ts-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ts2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-video-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-video2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-videostab-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-videostab2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv2.4-java', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv2.4-jni', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'opencv-data', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'opencv-doc', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-opencv', 'reference': '2.4.9.1+dfsg1-2+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcv-dev / libcv2.4 / libcvaux-dev / libcvaux2.4 / libhighgui-dev / etc');
}
