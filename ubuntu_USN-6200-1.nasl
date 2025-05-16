#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6200-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177934);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-29599",
    "CVE-2021-3610",
    "CVE-2021-20224",
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20246",
    "CVE-2021-20309",
    "CVE-2021-20312",
    "CVE-2021-20313",
    "CVE-2021-39212",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547",
    "CVE-2023-1289",
    "CVE-2023-1906",
    "CVE-2023-3195",
    "CVE-2023-3428",
    "CVE-2023-34151"
  );
  script_xref(name:"USN", value:"6200-1");
  script_xref(name:"IAVB", value:"2020-B-0076-S");
  script_xref(name:"IAVB", value:"2021-B-0017-S");
  script_xref(name:"IAVB", value:"2022-B-0032-S");
  script_xref(name:"IAVB", value:"2023-B-0020-S");
  script_xref(name:"IAVB", value:"2023-B-0038-S");
  script_xref(name:"IAVB", value:"2022-B-0019-S");
  script_xref(name:"IAVB", value:"2023-B-0046-S");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 ESM / 23.04 : ImageMagick vulnerabilities (USN-6200-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 ESM / 23.04 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6200-1 advisory.

    It was discovered that ImageMagick incorrectly handled the -authenticate option for password-protected
    PDF files. An attacker could possibly use this issue to inject additional shell commands and perform
    arbitrary code execution. This issue only affected Ubuntu 20.04 LTS. (CVE-2020-29599)

    It was discovered that ImageMagick incorrectly handled certain values when processing PDF files. If a user
    or automated system using ImageMagick were tricked into opening a specially crafted PDF file, an attacker
    could exploit this to cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
    (CVE-2021-20224)

    Zhang Xiaohui discovered that ImageMagick incorrectly handled certain values when processing image data.
    If a user or automated system using ImageMagick were tricked into opening a specially crafted image, an
    attacker could exploit this to cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
    (CVE-2021-20241, CVE-2021-20243)

    It was discovered that ImageMagick incorrectly handled certain values when processing visual effects based
    image files. By tricking a user into opening a specially crafted image file, an attacker could crash the
    application causing a denial of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-20244,
    CVE-2021-20309)

    It was discovered that ImageMagick incorrectly handled certain values when performing resampling
    operations. By tricking a user into opening a specially crafted image file, an attacker could crash the
    application causing a denial of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-20246)

    It was discovered that ImageMagick incorrectly handled certain values when processing thumbnail image
    data. By tricking a user into opening a specially crafted image file, an attacker could crash the
    application causing a denial of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-20312)

    It was discovered that ImageMagick incorrectly handled memory cleanup when performing certain
    cryptographic operations. Under certain conditions sensitive cryptographic information could be disclosed.
    This issue only affected Ubuntu 20.04 LTS. (CVE-2021-20313)

    It was discovered that ImageMagick did not use the correct rights when specifically excluded by a module
    policy. An attacker could use this issue to read and write certain restricted files. This issue only
    affected Ubuntu 20.04 LTS. (CVE-2021-39212)

    It was discovered that ImageMagick incorrectly handled memory under certain circumstances. If a user were
    tricked into opening a specially crafted image file, an attacker could possibly exploit this issue to
    cause a denial of service or other unspecified impact. This issue only affected Ubuntu 20.04 LTS.
    (CVE-2022-28463, CVE-2022-32545, CVE-2022-32546, CVE-2022-32547)

    It was discovered that ImageMagick incorrectly handled memory under certain circumstances. If a user were
    tricked into opening a specially crafted image file, an attacker could possibly exploit this issue to
    cause a denial of service or other unspecified impact. This issue only affected Ubuntu 22.04 LTS, Ubuntu
    22.10, and Ubuntu 23.04. (CVE-2021-3610, CVE-2023-1906, CVE-2023-3428)

    It was discovered that ImageMagick incorrectly handled certain values when processing specially crafted
    SVG files. By tricking a user into opening a specially crafted SVG file, an attacker could crash the
    application causing a denial of service. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
    Ubuntu 22.10, and Ubuntu 23.04. (CVE-2023-1289)

    It was discovered that ImageMagick incorrectly handled memory under certain circumstances. If a user were
    tricked into opening a specially crafted tiff file, an attacker could possibly exploit this issue to cause
    a denial of service or other unspecified impact. This issue only affected Ubuntu 22.04 LTS, Ubuntu 22.10,
    and Ubuntu 23.04. (CVE-2023-3195)

    It was discovered that ImageMagick incorrectly handled memory under certain circumstances. If a user were
    tricked into opening a specially crafted image file, an attacker could possibly exploit this issue to
    cause a denial of service or other unspecified impact. (CVE-2023-34151)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6200-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-5v5', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2-extra', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2', 'ubuntu_pro': TRUE},
    {'osver': '23.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6.q16 / etc');
}
