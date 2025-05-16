#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6621-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189915);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2023-5341");
  script_xref(name:"USN", value:"6621-1");
  script_xref(name:"IAVB", value:"2023-B-0077-S");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : ImageMagick vulnerability (USN-6621-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has packages installed that are affected by a
vulnerability as referenced in the USN-6621-1 advisory.

    It was discovered that ImageMagick incorrectly handled certain values when processing BMP files. An
    attacker could exploit this to cause a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6621-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++5");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-5v5', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2-extra', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm3', 'ubuntu_pro': TRUE}
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
