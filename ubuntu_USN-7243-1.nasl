#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7243-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214800);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id("CVE-2024-46461");
  script_xref(name:"IAVB", value:"2024-B-0148");
  script_xref(name:"USN", value:"7243-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS : VLC vulnerability (USN-7243-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are
affected by a vulnerability as referenced in the USN-7243-1 advisory.

    It was discovered that VLC incorrectly handled memory when reading an MMS stream. An attacker could
    possibly use this issue to cause a denial of service or execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7243-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-access-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-skins2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-output");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-splitter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-visualization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-zvbi");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libvlc-dev', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libvlc5', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libvlccore-dev', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libvlccore8', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-data', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-nox', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-sdl', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vlc-plugin-zvbi', 'pkgver': '2.2.2-5ubuntu0.16.04.5+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-zvbi', 'pkgver': '3.0.8-0ubuntu18.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.9.2-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.16-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.20-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvlc-bin / libvlc-dev / libvlc5 / libvlccore-dev / libvlccore8 / etc');
}
