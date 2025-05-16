#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7227-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-53432");
  script_xref(name:"USN", value:"7227-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : PCL vulnerability (USN-7227-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are
affected by a vulnerability as referenced in the USN-7227-1 advisory.

    It was discovered that PCL incorrectly handled certain malformed files. If a user or automated system were
    tricked into opening a specially crafted file, an attacker could possibly exploit this to cause a denial
    of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7227-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-apps1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-apps1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-apps1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-apps1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-apps1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-common1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-common1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-common1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-common1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-common1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-features1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-features1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-features1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-features1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-features1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-filters1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-filters1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-filters1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-filters1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-filters1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-io1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-io1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-io1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-io1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-io1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-kdtree1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-kdtree1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-kdtree1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-kdtree1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-kdtree1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-keypoints1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-keypoints1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-keypoints1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-keypoints1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-keypoints1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-ml1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-ml1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-ml1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-ml1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-octree1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-octree1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-octree1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-octree1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-octree1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-outofcore1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-outofcore1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-outofcore1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-outofcore1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-outofcore1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-people1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-people1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-people1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-people1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-people1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-recognition1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-recognition1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-recognition1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-recognition1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-recognition1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-registration1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-registration1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-registration1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-registration1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-registration1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-sample-consensus1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-sample-consensus1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-sample-consensus1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-sample-consensus1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-sample-consensus1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-search1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-search1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-search1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-search1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-search1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-segmentation1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-segmentation1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-segmentation1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-segmentation1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-segmentation1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-stereo1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-stereo1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-stereo1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-stereo1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-surface1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-surface1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-surface1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-surface1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-surface1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-tracking1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-tracking1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-tracking1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-tracking1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-tracking1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-visualization1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-visualization1.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-visualization1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-visualization1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl-visualization1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcl1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcl-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libpcl-apps1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-common1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-dev', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-features1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-filters1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-io1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-kdtree1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-keypoints1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-octree1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-outofcore1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-people1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-recognition1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-registration1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-sample-consensus1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-search1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-segmentation1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-surface1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-tracking1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl-visualization1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpcl1.7', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pcl-tools', 'pkgver': '1.7.2-14ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-apps1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-common1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-dev', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-features1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-filters1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-io1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-kdtree1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-keypoints1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-ml1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-octree1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-outofcore1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-people1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-recognition1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-registration1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-sample-consensus1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-search1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-segmentation1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-stereo1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-surface1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-tracking1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpcl-visualization1.8', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'pcl-tools', 'pkgver': '1.8.1+dfsg1-2ubuntu2.18.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-apps1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-common1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-dev', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-features1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-filters1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-io1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-kdtree1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-keypoints1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-ml1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-octree1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-outofcore1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-people1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-recognition1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-registration1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-sample-consensus1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-search1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-segmentation1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-stereo1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-surface1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-tracking1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpcl-visualization1.10', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'pcl-tools', 'pkgver': '1.10.0+dfsg-5ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-apps1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-common1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-dev', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-features1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-filters1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-io1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-kdtree1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-keypoints1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-ml1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-octree1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-outofcore1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-people1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-recognition1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-registration1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-sample-consensus1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-search1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-segmentation1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-stereo1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-surface1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-tracking1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpcl-visualization1.12', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pcl-tools', 'pkgver': '1.12.1+dfsg-3ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-apps1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-common1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-dev', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-features1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-filters1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-io1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-kdtree1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-keypoints1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-ml1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-octree1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-outofcore1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-people1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-recognition1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-registration1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-sample-consensus1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-search1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-segmentation1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-stereo1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-surface1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-tracking1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libpcl-visualization1.14', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'pcl-tools', 'pkgver': '1.14.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.10', 'pkgname': 'libpcl-apps1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-common1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-dev', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-features1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-filters1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-io1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-kdtree1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-keypoints1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-ml1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-octree1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-outofcore1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-people1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-recognition1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-registration1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-sample-consensus1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-search1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-segmentation1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-stereo1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-surface1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-tracking1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpcl-visualization1.14', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'pcl-tools', 'pkgver': '1.14.0+dfsg-3ubuntu0.2', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpcl-apps1.10 / libpcl-apps1.12 / libpcl-apps1.14 / etc');
}
