#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4818-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183130);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-18009",
    "CVE-2019-14491",
    "CVE-2019-14492",
    "CVE-2019-14493",
    "CVE-2019-15939"
  );
  script_xref(name:"USN", value:"4818-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM : OpenCV vulnerabilities (USN-4818-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4818-1 advisory.

    It was discovered that OpenCV did not properly manage certain objects, leading to a divide-by-zero. If a
    user were tricked into loading a specially crafted file, a remote attacker could potentially use this
    issue to cause a denial of service or possibly execute arbitrary code. (CVE-2019-15939)

    It was discovered that OpenCV did not properly manage certain files, leading to an out of bounds read. If
    a user were tricked into loading a specially crafted file, a remote attacker could potentially use this
    issue to make OpenCV crash, resulting in a denial of service. This issue was only fixed in Ubuntu 18.04
    ESM. (CVE-2019-14491, CVE-2019-14492)

    It was discovered that OpenCV did not properly manage certain XML data, leading to a NULL pointer
    dereference. If a user were tricked into loading a specially crafted file, a remote attacker could
    potentially use this issue to make OpenCV crash, resulting in a denial of service. This issue was only
    fixed in Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2019-14493)

    It was discovered that OpenCV did not properly manage certain files, leading to a heap-based buffer
    overflow. If a user were tricked into loading a specially crafted file, a remote attacker could
    potentially use this issue to cause a denial of service or possibly execute arbitrary code. This issue
    only affected Ubuntu 18.04 ESM. (CVE-2017-18009)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4818-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14491");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcv2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcvaux-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcvaux2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhighgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhighgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-calib3d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-calib3d2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-calib3d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-calib3d3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-contrib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-contrib2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-contrib2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-contrib3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-core2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-core2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-core3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-features2d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-features2d2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-features2d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-features2d3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-flann-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-flann2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-flann2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-flann3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-gpu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-gpu2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-gpu2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-highgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-highgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-highgui2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-highgui3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgcodecs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgcodecs3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgproc2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgproc2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-imgproc3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-legacy2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-legacy2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ml2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ml2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ml3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-objdetect-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-objdetect2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-objdetect2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-objdetect3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ocl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ocl2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ocl2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-photo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-photo2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-photo2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-photo3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-shape-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-shape3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-stitching-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-stitching2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-stitching2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-stitching3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-superres-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-superres2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-superres2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-superres3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ts-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ts2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-ts2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-video-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-video2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-video2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-video3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videoio-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videoio3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videostab-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videostab2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videostab2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-videostab3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-viz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv-viz3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv2.4-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv3.2-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopencv3.2-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:opencv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-opencv");
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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libcv-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcv2.4', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcvaux-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcvaux2.4', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libhighgui-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libhighgui2.4', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-calib3d-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-calib3d2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-contrib-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-contrib2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-core-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-core2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-features2d-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-features2d2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-flann-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-flann2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-gpu-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-gpu2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-highgui-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-highgui2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-imgproc-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-imgproc2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-legacy-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-legacy2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ml-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ml2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-objdetect-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-objdetect2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ocl-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ocl2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-photo-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-photo2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-stitching-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-stitching2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-superres-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-superres2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ts-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-ts2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-video-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-video2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-videostab-dev', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv-videostab2.4v5', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv2.4-java', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libopencv2.4-jni', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'opencv-data', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-opencv', 'pkgver': '2.4.9.1+dfsg-1.5ubuntu1.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-calib3d-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-calib3d3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-contrib-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-contrib3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-core-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-core3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-features2d-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-features2d3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-flann-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-flann3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-highgui-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-highgui3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-imgcodecs-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-imgcodecs3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-imgproc-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-imgproc3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-ml-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-ml3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-objdetect-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-objdetect3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-photo-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-photo3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-shape-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-shape3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-stitching-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-stitching3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-superres-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-superres3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-ts-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-video-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-video3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-videoio-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-videoio3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-videostab-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-videostab3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-viz-dev', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv-viz3.2', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv3.2-java', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libopencv3.2-jni', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'opencv-data', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-opencv', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-opencv', 'pkgver': '3.2.0+dfsg-4ubuntu0.1+esm3', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcv-dev / libcv2.4 / libcvaux-dev / libcvaux2.4 / libhighgui-dev / etc');
}
